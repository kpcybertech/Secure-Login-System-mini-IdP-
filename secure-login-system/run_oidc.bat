@echo off
cd /d "%~dp0"
call .\venv\Scripts\activate
python mainsecurelogin.py
pause