@echo off
setlocal
title TERMINAL - ZTAP IRONCLAD
cls

echo ====================================================
echo             TERMINAL - ZTAP PROTOCOL
echo              IRONCLAD v3.1 (HARDENED)
echo ====================================================
echo.

:: Asegurarse de estar en el directorio del script
cd /d "%~dp0"

:: 0. Limpieza forzada de colisiones
echo [0/3] Liberando recursos y puertos...
taskkill /f /im node.exe >nul 2>&1
taskkill /f /im tor.exe >nul 2>&1

:: 1. Verificar Node.js
echo [1/3] Verificando entorno Node.js...
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Node.js no detectado en el sistema.
    echo Descargalo en: https://nodejs.org/
    pause
    exit /b
)

:: 2. Verificar Dependencias
echo [2/3] Validando integridad de modulos...
if not exist "node_modules\ws" (
    echo Modulos faltantes. Instalando dependencias...
    call npm install
    if %errorlevel% neq 0 (
        echo.
        echo [ERROR] Fallo al instalar dependencias de NPM.
        pause
        exit /b
    )
)

:: 3. Lanzamiento
echo [3/3] Iniciando launcher...
echo.

node launcher.js

if %errorlevel% neq 0 (
    echo.
    echo [CRASH] El sistema se detuvo inesperadamente (Codigo: %errorlevel%)
    pause
)

endlocal
