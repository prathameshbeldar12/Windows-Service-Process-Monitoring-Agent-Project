@echo off
echo ========================================================
echo SENTINEL EDR AGENT BUILD SCRIPT
echo ========================================================
echo.
echo [INFO] Transitioning to agent directory...
cd agent
echo [INFO] Running PyInstaller compilation...
pyinstaller --clean agent.spec
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] PyInstaller compilation failed!
    cd ..
    exit /b %ERRORLEVEL%
)
echo.
echo [SUCCESS] Sentinel Agent executable built successfully!
echo [SUCCESS] Executable path: agent/dist/sentinel_agent.exe
cd ..
