@echo off
title FactoryShield - Industrial Enterprise Honeypot
if "%FACTORYSHIELD_ADMIN_USERNAME%"=="" set FACTORYSHIELD_ADMIN_USERNAME=admin
if "%FACTORYSHIELD_ADMIN_PASSWORD%"=="" set FACTORYSHIELD_ADMIN_PASSWORD=admin123
if "%FACTORYSHIELD_COOKIE_SECURE%"=="" set FACTORYSHIELD_COOKIE_SECURE=false

echo ========================================================
echo Starting FactoryShield (Jordan Industrial Manufacturing)
echo Admin Credentials:
echo   Username: %FACTORYSHIELD_ADMIN_USERNAME%
echo   Password: %FACTORYSHIELD_ADMIN_PASSWORD%
echo Web Dashboard will be available at http://localhost:5000
echo ========================================================
python run.py
pause
