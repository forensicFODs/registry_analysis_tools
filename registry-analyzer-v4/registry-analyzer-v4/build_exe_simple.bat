@echo off
chcp 65001 >nul
REM Windows EXE Builder - English Only Version
REM For: C:\Users\wd\Desktop\registry-analyzer-v4\registry-analyzer-v4

echo ========================================
echo Registry Analyzer v4.0 - Build EXE
echo ========================================
echo.

REM Check PyInstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PyInstaller not installed
    echo.
    echo Installing PyInstaller...
    pip install pyinstaller
    if errorlevel 1 (
        echo [FAIL] Cannot install PyInstaller
        echo Please check Python installation
        pause
        exit /b 1
    )
    echo [OK] PyInstaller installed
    echo.
)

REM Clean previous build
echo Cleaning previous build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec
echo [OK] Cleaned
echo.

REM Build EXE
echo Building EXE file...
echo This may take 1-2 minutes...
echo.

pyinstaller --onefile --windowed --name=RegistryAnalyzer --add-data="core;core" --add-data="analyzers;analyzers" --add-data="gui;gui" --add-data="utils;utils" --hidden-import=tkinter --hidden-import=requests --clean main.py

echo.
if exist dist\RegistryAnalyzer.exe (
    echo ========================================
    echo [SUCCESS] Build completed!
    echo ========================================
    echo.
    echo EXE Location:
    echo %CD%\dist\RegistryAnalyzer.exe
    echo.
    echo File Info:
    dir dist\RegistryAnalyzer.exe | find "RegistryAnalyzer.exe"
    echo.
    echo Next Steps:
    echo   1. Open folder: explorer dist
    echo   2. Double-click: RegistryAnalyzer.exe
    echo   3. Or run: dist\RegistryAnalyzer.exe
    echo.
    
    set /p OPEN="Open dist folder now? (y/n): "
    if /i "%OPEN%"=="y" (
        explorer dist
    )
) else (
    echo ========================================
    echo [FAIL] Build failed
    echo ========================================
    echo.
    echo dist\RegistryAnalyzer.exe not found
    echo.
    echo Possible reasons:
    echo   1. Python not installed
    echo   2. PyInstaller error
    echo   3. Missing dependencies
    echo.
    echo Check error messages above
)

echo.
pause
