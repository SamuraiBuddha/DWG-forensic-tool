@echo off
REM ============================================================================
REM EMAIL TIMELINE EXTRACTION - AUTOMATED WORKFLOW
REM Kara Murphy vs Danny Garcia (Case 2026-001)
REM ============================================================================

echo.
echo ========================================================================
echo EMAIL TIMELINE EXTRACTION TOOL
echo Kara Murphy vs Danny Garcia (Case 2026-001)
echo ========================================================================
echo.

REM Step 1: Check Python installation
echo [STEP 1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found. Please install Python 3.7 or higher.
    pause
    exit /b 1
)
echo [OK] Python installed
echo.

REM Step 2: Install extract-msg library
echo [STEP 2/5] Installing extract-msg library...
pip install extract-msg
if errorlevel 1 (
    echo [FAIL] Failed to install extract-msg library
    pause
    exit /b 1
)
echo [OK] extract-msg library installed
echo.

REM Step 3: Verify network share access
echo [STEP 3/5] Verifying network share access...
if exist "\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails\" (
    echo [OK] Network share accessible
) else (
    echo [FAIL] Network share not accessible: \\adam\DataPool\
    echo.
    echo TROUBLESHOOTING:
    echo   1. Verify network connection
    echo   2. Map network drive: net use Z: \\adam\DataPool\
    echo   3. Contact IT for permissions
    echo.
    pause
    exit /b 1
)
echo.

REM Step 4: Run environment verification
echo [STEP 4/5] Running environment verification...
python verify_email_parser_setup.py
if errorlevel 1 (
    echo [FAIL] Environment verification failed
    echo Please resolve issues above and re-run this script.
    pause
    exit /b 1
)
echo.

REM Step 5: Run email timeline parser
echo [STEP 5/5] Running email timeline parser...
echo.
echo ========================================================================
echo PARSING 65 MSG FILES
echo ========================================================================
echo.

python email_timeline_parser.py

if errorlevel 1 (
    echo.
    echo [FAIL] Email parser encountered errors
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo EMAIL TIMELINE EXTRACTION COMPLETE
echo ========================================================================
echo.
echo OUTPUT LOCATION:
echo   \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\EMAIL_TIMELINE_ANALYSIS\
echo.
echo NEXT STEPS:
echo   1. Review SMOKING_GUN_EMAILS.txt for top 10 critical emails
echo   2. Check EMAIL_KEYWORD_ANALYSIS.txt for fraud indicators
echo   3. Validate EMAIL_TIMELINE_MASTER.csv has 65 rows
echo   4. Use DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt for exhibit prep
echo.
echo Press any key to exit...
pause >nul
