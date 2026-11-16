@echo off
setlocal
py -3 "%~dp0AmneziaAppKillSwitch.py" 2>nul
if not errorlevel 1 goto :done
python "%~dp0AmneziaAppKillSwitch.py"
if not errorlevel 1 goto :done
echo.
echo Python 3 with Tkinter is required. Install it from python.org, then run this file again.
pause
:done

