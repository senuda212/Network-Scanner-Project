@echo off
setlocal

REM setup.bat - Windows launcher for the Network Scanner project
REM Handles help/cli/smoke modes first, then installs dependencies,
REM activates the venv, and starts the requested mode.

pushd "%~dp0"
set "MODE=%~1"

if /I "%MODE%"=="help" goto :help
if /I "%MODE%"=="--help" goto :help
if /I "%MODE%"=="-h" goto :help
if /I "%MODE%"=="cli" goto :cli
if /I "%MODE%"=="smoke" goto :smoke

goto :setup

:setup
set "VENV_DIR=.venv"
echo Project: %CD%

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Creating virtual environment in %VENV_DIR%...
    py -3 -m venv "%VENV_DIR%"
    if errorlevel 1 (
        python -m venv "%VENV_DIR%"
        if errorlevel 1 (
            echo Failed to create virtual environment.
            popd
            exit /b 1
        )
    )
)

echo Installing requirements...
call "%VENV_DIR%\Scripts\activate.bat"
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

echo Running quick compile checks...
python -m py_compile scanner.py
if errorlevel 1 (
    echo Compile checks failed.
    popd
    exit /b 1
)
python -m py_compile gui.py
if errorlevel 1 (
    echo Compile checks failed.
    popd
    exit /b 1
)

goto :gui

:cli
set "VENV_DIR=.venv"
echo Project: %CD%
if not exist "%VENV_DIR%\Scripts\python.exe" goto :setup
call "%VENV_DIR%\Scripts\activate.bat"
shift
python scanner.py %*
popd
exit /b %errorlevel%

:smoke
set "VENV_DIR=.venv"
echo Project: %CD%
if not exist "%VENV_DIR%\Scripts\python.exe" goto :setup
call "%VENV_DIR%\Scripts\activate.bat"
python scanner.py --target 127.0.0.1 --ports 22,80 --threads 20 --timeout 0.5 --output smoke_results.txt
if not errorlevel 1 echo Smoke results saved to smoke_results.txt
popd
exit /b %errorlevel%

:gui
echo Starting GUI (press Ctrl+C to quit)...
python gui.py
popd
exit /b %errorlevel%

:help
echo Usage: setup.bat [gui^|cli^|smoke^|help] [scanner args...]
echo.
echo Commands:
echo   gui       Start the desktop GUI (default)
echo   cli       Run scanner.py and pass the remaining args
echo   smoke     Run a quick localhost smoke test
echo   help      Show this help text
echo.
echo Examples:
echo   setup.bat
echo   setup.bat cli -- --target 127.0.0.1 --ports 22,80
echo   setup.bat smoke
popd
exit /b 0
