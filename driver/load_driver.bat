@echo off
:: ================================================================
::  Load CorMem.sys Kernel Driver
::  Run as Administrator
:: ================================================================

setlocal

set DRIVER_NAME=CORMEM
set DRIVER_PATH=%~dp0Cormem.sys

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo     Right-click ^> Run as administrator
    pause
    exit /b 1
)

:: Check driver file exists
if not exist "%DRIVER_PATH%" (
    echo [!] Driver not found: %DRIVER_PATH%
    pause
    exit /b 1
)

:: Check if already running
sc query %DRIVER_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    sc query %DRIVER_NAME% | findstr /i "RUNNING" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [*] %DRIVER_NAME% is already running.
        pause
        exit /b 0
    )
    echo [*] Service exists but not running — starting...
    sc start %DRIVER_NAME%
    goto :check
)

:: Create and start the service
echo [*] Creating service %DRIVER_NAME%...
echo     Path: %DRIVER_PATH%
sc create %DRIVER_NAME% type=kernel binPath="%DRIVER_PATH%"
if %errorlevel% neq 0 (
    echo [!] sc create failed — error %errorlevel%
    pause
    exit /b 1
)

echo [*] Starting driver...
sc start %DRIVER_NAME%

:check
timeout /t 1 /nobreak >nul
sc query %DRIVER_NAME% | findstr /i "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] %DRIVER_NAME% loaded successfully.
) else (
    echo [!] Driver failed to start. Check Event Viewer for details.
    echo     Common causes:
    echo       - Driver Signature Enforcement is enabled
    echo       - HVCI / Secure Boot blocking unsigned drivers
    echo     To disable DSE for testing: bcdedit /set testsigning on
    sc query %DRIVER_NAME%
)

pause
exit /b 0
