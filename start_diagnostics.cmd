@echo off
where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 "%~dp0run.py" %*
    exit /b
)
where python >nul 2>nul
if %errorlevel% equ 0 (
    python "%~dp0run.py" %*
    exit /b
)
echo Install Python 3.9+ from https://www.python.org/downloads/ and try again.
exit /b 2
