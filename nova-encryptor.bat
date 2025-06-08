@echo off
REM NovaEncryptor v2.0 Launcher

REM Check if virtual environment exists
if not exist "nova_env" (
    echo ❌ Virtual environment not found. Run setup.py first.
    pause
    exit /b 1
)

REM Activate virtual environment and run
call nova_env\Scripts\activate
python src\nova_encryptor.py %*
pause
