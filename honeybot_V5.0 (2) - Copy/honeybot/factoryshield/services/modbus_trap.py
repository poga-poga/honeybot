"""
FactoryShield: Native Modbus TCP Decoy Trap (Port 502 / 5502)
Emulates a Siemens SIMATIC S7-1200 / Schneider Electric PLC for industrial honeypot detection.
Supports Modbus MBAP, Function 0x01 (Coils), 0x03 (Holding Registers), 0x06/0x10 (Write),
and Function 0x2B (Device Identification for Nmap / ICS scanners).
"""
import socket
import struct
import threading
import time
from typing import Tuple, Optional
from datetime import datetime, timezone

from factoryshield.engine.detector import detector_engine

MODBUS_DEVICE_ID = {
    0x00: "Siemens AG",                                   # Vendor Name
    0x01: "SIMATIC S7-1200 CPU 1214C (DC/DC/DC)",        # Product Code
    0x02: "v4.2.1-JIM-PROD",                             # Major / Minor Revision
    0x03: "http://www.siemens.com/simatic",              # Vendor URL
    0x04: "Jordan Industrial Manufacturing Line 07 PLC", # Product Name
    0x05: "6ES7 214-1AG40-0XB0",                         # Model Name
}

# Simulated Holding Registers (40001 - 40120)
REGISTERS = {
    1: 1800,   # Spindle RPM
    2: 452,    # Hydraulic Pressure (45.2 Bar)
    3: 684,    # Coolant Temperature (68.4 C)
    4: 142,    # CPU Load (14.2%)
    5: 1,      # Line-01 Safety Relay (1 = Closed/Safe)
    6: 1,      # Line-02 Safety Relay
    7: 1,      # Line-07 Black Project Interlock (1 = Armed)
    108: 0xDEAD # Canary Register: 40108 Emergency Interlock Bypass
}

class ModbusTrapServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 502, fallback_port: int = 5502):
        self.host = host
        self.port = port
        self.fallback_port = fallback_port
        self.actual_port = port
        self.server_sock: Optional[socket.socket] = None
        self.running = False

    def handle_modbus_pdu(self, client_ip: str, function_code: int, pdu_data: bytes) -> bytes:
        """
        Processes standard Modbus functions and triggers FactoryShield detection on suspicious probes.
        """
        # Function 0x03: Read Holding Registers
        if function_code == 0x03:
            if len(pdu_data) < 4:
                return bytes([function_code | 0x80, 0x03]) # Illegal Data Value
            start_addr, quantity = struct.unpack(">HH", pdu_data[:4])
            
            # Check for Canary Register 40108 (addr 108 or 107)
            if start_addr <= 108 <= (start_addr + quantity):
                self._trigger_canary_alert(
                    client_ip=client_ip,
                    action="read_holding_registers",
                    resource="plc-sim01.jim.corp:Modbus_Reg_40108_Safety_Override",
                    details=f"Probed decoy Canary holding register 40108 (Safety Interlock Override) at addr {start_addr}"
                )

            # Return register values
            byte_count = quantity * 2
            response_bytes = bytearray([0x03, byte_count])
            for i in range(quantity):
                reg_idx = start_addr + i
                val = REGISTERS.get(reg_idx, 0)
                response_bytes.extend(struct.pack(">H", val))
            return bytes(response_bytes)

        # Function 0x01: Read Coils
        elif function_code == 0x01:
            if len(pdu_data) < 4:
                return bytes([function_code | 0x80, 0x03])
            start_addr, quantity = struct.unpack(">HH", pdu_data[:4])
            # Return coil status (byte count = 1, coil 1=ON)
            byte_count = (quantity + 7) // 8
            coil_data = bytes([0x55] * byte_count) # Simulated coil bits
            return bytes([0x01, byte_count]) + coil_data

        # Function 0x05 / 0x06 / 0x10: Write commands (UNAUTHORIZED WRITE ATTEMPT)
        elif function_code in [0x05, 0x06, 0x0F, 0x10]:
            self._trigger_canary_alert(
                client_ip=client_ip,
                action="unauthorized_modbus_write",
                resource="plc-sim01.jim.corp:PLC_Coil_Write_Tamper",
                details=f"Unauthorized Modbus write command (FC {hex(function_code)}) attempted on PLC controller."
            )
            # Acknowledge or return illegal data address to keep attacker engaged
            return bytes([function_code]) + pdu_data[:4]

        # Function 0x2B / 0x0E: Read Device Identification (Nmap --script modbus-discover)
        elif function_code == 0x2B:
            # MEI response for device identification
            resp = bytearray([0x2B, 0x0E, 0x01, 0x83, 0x00, 0x00, len(MODBUS_DEVICE_ID)])
            for obj_id, obj_val in MODBUS_DEVICE_ID.items():
                val_bytes = obj_val.encode("utf-8")
                resp.extend(struct.pack("BB", obj_id, len(val_bytes)))
                resp.extend(val_bytes)
            return bytes(resp)

        # Default: Exception 0x01 (Illegal Function)
        return bytes([function_code | 0x80, 0x01])

    def _trigger_canary_alert(self, client_ip: str, action: str, resource: str, details: str):
        """
        Feeds Modbus attack event directly into FactoryShield's correlation engine.
        """
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "source_host": client_ip,
                "target_host": "plc-sim01.jim.corp",
                "username": "external_attacker",
                "resource": resource,
                "action": action,
                "status": "FLAGGED",
                "details": details,
                "service_name": f"Modbus TCP Industrial Controller ({self.actual_port})"
            }
        ]
        detector_engine.process_scenario_events(events, session_id=f"MODBUS-PROBE-{int(time.time())}")

    def handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        client_ip = client_addr[0]
        try:
            while self.running:
                header = client_sock.recv(7)
                if not header or len(header) < 7:
                    break

                # Parse MBAP Header
                trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
                if proto_id != 0:
                    break

                pdu = client_sock.recv(length - 1)
                if not pdu:
                    break

                function_code = pdu[0]
                pdu_data = pdu[1:]

                response_pdu = self.handle_modbus_pdu(client_ip, function_code, pdu_data)

                # Build MBAP Response Header
                resp_length = len(response_pdu) + 1
                resp_header = struct.pack(">HHHB", trans_id, proto_id, resp_length, unit_id)
                client_sock.sendall(resp_header + response_pdu)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def start(self):
        self.running = True
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.port))
            self.actual_port = self.port
        except OSError:
            # Fall back to fallback port if primary port is busy
            self.actual_port = self.fallback_port
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.actual_port))

        self.server_sock.listen(10)
        print(f"[*] FactoryShield Native Modbus TCP Controller running on {self.host}:{self.actual_port}")

        while self.running:
            try:
                client_sock, client_addr = self.server_sock.accept()
                t = threading.Thread(target=self.handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

def start_modbus_trap_thread(host: str = "0.0.0.0", port: int = 502) -> ModbusTrapServer:
    server = ModbusTrapServer(host=host, port=port)
    t = threading.Thread(target=server.start, daemon=True)
    t.start()
    return server
