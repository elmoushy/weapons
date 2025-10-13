@echo off
REM ========================================
REM WeaponBackend - Commit to GitHub
REM ========================================
REM This script safely commits your Docker files to GitHub
REM Your .env file will NOT be uploaded (protected by .gitignore)
REM ========================================

echo ========================================
echo  WeaponBackend GitHub Upload Script
echo ========================================
echo.

REM Check if we're in a git repository
git status >nul 2>&1
if errorlevel 1 (
    echo ERROR: Not a git repository!
    echo Please run this script from the WeaponBackend directory.
    pause
    exit /b 1
)

echo [1/5] Checking current status...
git status
echo.

REM Check if .env is in the status (it shouldn't be)
git status | findstr /C:".env" >nul
if not errorlevel 1 (
    echo.
    echo WARNING: .env file is being tracked by Git!
    echo Removing it from Git tracking...
    git rm --cached .env
    echo .env removed from Git tracking.
    echo.
)

echo [2/5] Verifying .env is protected...
type .gitignore | findstr /C:".env" >nul
if errorlevel 1 (
    echo ERROR: .env is not in .gitignore!
    echo This is a security risk. Please add it.
    pause
    exit /b 1
) else (
    echo SUCCESS: .env is protected by .gitignore
)
echo.

echo [3/5] Adding Docker and deployment files...
git add .
echo.

echo [4/5] Files to be committed:
git status
echo.

echo [5/5] Ready to commit!
echo.
set /p confirm="Do you want to commit these changes? (yes/no): "

if /i "%confirm%"=="yes" (
    echo.
    set /p message="Enter commit message (or press Enter for default): "
    
    if "%message%"=="" (
        set message=Add Docker and AWS deployment configuration
    )
    
    echo Committing with message: %message%
    git commit -m "%message%"
    
    echo.
    echo ========================================
    echo  Commit Successful!
    echo ========================================
    echo.
    echo Next steps:
    echo 1. Push to GitHub: git push origin main
    echo 2. Read QUICKSTART.md for deployment guide
    echo 3. Your .env file is safe and NOT uploaded
    echo.
    
    set /p push="Do you want to push to GitHub now? (yes/no): "
    
    if /i "%push%"=="yes" (
        echo Pushing to GitHub...
        git push origin main
        echo.
        echo ========================================
        echo  Successfully pushed to GitHub!
        echo ========================================
        echo.
        echo Your code is now on GitHub (without .env file)
        echo Next: Read QUICKSTART.md to deploy to AWS EC2
    ) else (
        echo.
        echo Remember to push when ready: git push origin main
    )
) else (
    echo.
    echo Commit cancelled. No changes made.
)

echo.
pause
