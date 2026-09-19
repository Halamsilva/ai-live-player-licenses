@echo off
setlocal
chcp 65001 >nul
title AI Live Player - Painel de Licencas
cd /d "%~dp0"
set /p ADMIN_PASSWORD=<senha.txt
echo =====================================
echo  AI Live Player - Painel de Licencas
echo  Senha de administrador: %ADMIN_PASSWORD%
echo  Acesse: http://localhost:8457
echo =====================================
echo.
echo Deixe esta janela aberta enquanto usar o painel.
node server.cjs
pause