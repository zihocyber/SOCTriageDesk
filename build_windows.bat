@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
where py >nul 2>nul
if not errorlevel 1 if not exist ".venv\Scripts\python.exe" set "PYTHON=py"

"%PYTHON%" -m pip install --upgrade pyinstaller
if errorlevel 1 exit /b %errorlevel%

"%PYTHON%" -m PyInstaller --noconfirm --clean --onefile --windowed --name SOCTriageDesk Main.py
if errorlevel 1 exit /b %errorlevel%

echo.
echo Build complete: dist\SOCTriageDesk.exe
endlocal