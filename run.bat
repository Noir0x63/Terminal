@echo off
title TERMINAL - TOR SERVICE LAUNCHER
cls
echo ====================================================
echo             TERMINAL - BUILD ^& LAUNCH
echo ====================================================
echo.

:: -1. Limpiar procesos anteriores
echo [0/2] Limpiando procesos en puerto 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| find ":3000" ^| find "LISTENING"') do (
    echo Cerrando instancia previa (PID %%a)...
    taskkill /F /PID %%a >nul 2>&1
)

:: 0. Verificar Node.js
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js no esta instalado o no se encuentra en el PATH.
    echo Por favor, instala Node.js desde https://nodejs.org/
    echo.
    pause
    exit /b
)

:: 1. Verificar dependencias
echo [1/2] Verificando dependencias...
if not exist node_modules (
    echo Instalando dependencias necesarias...
    call npm install
    if errorlevel 1 (
        echo.
        echo ERROR: No se pudieron instalar las dependencias. 
        echo Revisa tu conexion a internet o los permisos de la carpeta.
        pause
        exit /b
    )
) else (
    echo Dependencias encontradas.
)

:: 2. Verificar Tor
if not exist "Tor\tor.exe" (
    echo.
    echo ERROR: No se encuentra 'Tor\tor.exe'.
    echo Asegurate de que la carpeta 'Tor' contiene el ejecutable de Tor.
    pause
    exit /b
)

echo.
echo [2/2] Iniciando sistema completo...
echo.

:: Ejecutar el launcher
node launcher.js

:: Si llegamos aqui es porque el proceso termino
if %errorlevel% neq 0 (
    echo.
    echo ERROR: El sistema se ha detenido con el codigo: %errorlevel%
) else (
    echo.
    echo El sistema se ha cerrado correctamente.
)

pause
