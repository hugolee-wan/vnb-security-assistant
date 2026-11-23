@echo off
chcp 65001 >nul
setlocal
set "DIR=%~dp0"
set "VNB_HOME=%DIR%..\.."
start "" "%DIR%vnb-security-assistant.exe" %*
