@echo off
REM ================================================
REM Add Screenshots Script Launcher
REM ================================================
REM This script runs the add_screenshots.py script
REM and logs output to screenshots.log
REM ================================================

cd /d "%~dp0"

echo ================================================
echo Add Screenshots to Data.json
echo ================================================
echo.

REM Check if .env file exists and load it
if exist ".env" (
    echo Loading API keys from .env...
    for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
        if not "%%a"=="" if not "%%a:~0,1%"=="#" (
            set "%%a=%%b"
        )
    )
) else (
    echo WARNING: No .env file found!
    echo Create .env from .env.example and add your API keys
    echo.
)

REM Parse arguments
set ARGS=
set LIMIT=
set SUBMIT=

:parse_args
if "%~1"=="" goto run
if /i "%~1"=="--limit" (
    set LIMIT=%~2
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--submit" (
    set SUBMIT=--submit
    shift
    goto parse_args
)
if /i "%~1"=="--dry-run" (
    set ARGS=%ARGS% --dry-run
    shift
    goto parse_args
)
shift
goto parse_args

:run
if defined LIMIT (
    set ARGS=%ARGS% --limit %LIMIT%
)
if defined SUBMIT (
    set ARGS=%ARGS% --submit
)

echo Running: python add_screenshots.py %ARGS%
echo Log file: screenshots.log
echo.
echo Press Ctrl+C to stop at any time (progress will be saved)
echo ================================================
echo.

python add_screenshots.py %ARGS%

echo.
echo ================================================
echo Done! Check screenshots.log for details.
echo ================================================
pause
