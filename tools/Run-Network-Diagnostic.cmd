@echo off
set "SIMPLEWALL_EXE=%~dp0simplewall.exe"

if not exist "%SIMPLEWALL_EXE%" set "SIMPLEWALL_EXE=%~dp0..\bin\64\simplewall.exe"

if not exist "%SIMPLEWALL_EXE%" (
	echo simplewall.exe was not found beside this launcher.
	exit /b 1
)

"%SIMPLEWALL_EXE%" -networkdiagnostic
