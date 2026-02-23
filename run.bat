@echo off
chcp 65001 >nul
cls

echo ============================================================
echo 🎮 Free Fire Login - Simple Version
echo ============================================================
echo.

REM التحقق من وجود Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python غير مثبت!
    echo ثبتو من: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM التحقق من وجود pip
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ pip غير مثبت!
    pause
    exit /b 1
)

REM التحقق من وجود المكتبات
echo 🔍 التحقق من المكتبات...
pip show requests >nul 2>&1
if %errorlevel% neq 0 (
    echo 📦 تثبيت المكتبات...
    pip install -r requirements.txt
)

REM التحقق من وجود config.json
if not exist config.json (
    echo ❌ ملف config.json غير موجود!
    if exist config.json.example (
        echo 📝 نسخ ملف النموذج...
        copy config.json.example config.json
        echo ✅ تم إنشاء config.json
        echo ⚠️  عدل الملف وحط Access Token و Open ID ديالك
    )
    pause
    exit /b 1
)

echo ✅ كلشي مزيان!
echo 🚀 بداية التشغيل...
echo.

REM تشغيل السكريپت
python main.py

pause
