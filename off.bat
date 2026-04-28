@echo off
title TERMINAL - SYSTEM SHUTDOWN
cls
echo ====================================================
echo             TERMINAL - FORCING SHUTDOWN
echo ====================================================
echo.

echo [1/2] Cerrando procesos de Node.js...
taskkill /F /IM node.exe /T >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| find ":3000" ^| find "LISTENING"') do taskkill /F /PID %%a >nul 2>&1

echo [2/2] Cerrando procesos de Tor...
taskkill /F /IM tor.exe /T >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| find ":9050" ^| find "LISTENING"') do taskkill /F /PID %%a >nul 2>&1

echo.
echo ====================================================
echo      SISTEMA PURGADO Y PUERTOS LIBERADOS
echo ====================================================
echo.
pause
