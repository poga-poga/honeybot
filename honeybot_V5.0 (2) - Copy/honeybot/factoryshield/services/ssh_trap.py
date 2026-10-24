"""
FactoryShield: SSH Decoy Trap Server (Port 2222)
Simulates cad-srv01.jim.corp - Engineering SSH Gateway
"""
import socket
import threading
import time
from datetime import datetime
from factoryshield.engine.detector import detector_engine

class SSHTrapServer:
    def __init__(self, host="0.0.0.0", port=2222):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[+] SSH Decoy Trap running on {self.host}:{self.port} (cad-srv01.jim.corp)")
        except Exception as e:
            print(f"[-] Could not bind SSH Decoy Trap to port {self.port}: {e}")
            return

        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, client_sock, client_addr):
        client_ip = client_addr[0]
        try:
            # Send standard SSH banner with JIM identification
            banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 (JIM-Engineering-Vault)\r\n"
            client_sock.sendall(banner)

            client_sock.settimeout(4.0)
            data = client_sock.recv(1024)

            # Extract possible username/command or raw packet
            raw_str = data.decode("utf-8", errors="ignore").strip()
            username = "unknown_ssh_actor"
            if "ssh" in raw_str.lower() or len(raw_str) > 0:
                words = raw_str.split()
                if len(words) > 1:
                    username = words[0][:30]

            # Log event to FactoryShield Engine
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "username": username if username != "unknown_ssh_actor" else "svc_eng_backup",
                "source_host": client_ip,
                "target_host": "cad-srv01.jim.corp",
                "resource": "cad/repo/ssh_session",
                "action": "auth_bruteforce",
                "status": "DENIED",
                "details": f"Raw payload: {raw_str[:50]}"
            }
            detector_engine.process_scenario_events([event], session_id=f"SSHTRAP-{client_ip}")

            time.sleep(1.0)
            client_sock.sendall(b"Permission denied (publickey,password).\r\n")
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

def start_ssh_trap_thread(host="0.0.0.0", port=2222):
    trap = SSHTrapServer(host=host, port=port)
    t = threading.Thread(target=trap.start, daemon=True, name="SSHTrap")
    t.start()
    return trap
