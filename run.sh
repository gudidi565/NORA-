#!/bin/bash

echo "============================================================"
echo "🎮 Free Fire Login - Simple Version"
echo "============================================================"
echo ""

# التحقق من وجود Python
if ! command -v python3 &> /dev/null
then
    echo "❌ Python 3 غير مثبت!"
    echo "ثبتو أولاً: sudo apt install python3"
    exit 1
fi

# التحقق من وجود pip
if ! command -v pip3 &> /dev/null
then
    echo "❌ pip3 غير مثبت!"
    echo "ثبتو أولاً: sudo apt install python3-pip"
    exit 1
fi

# التحقق من وجود المكتبات
echo "🔍 التحقق من المكتبات..."
pip3 show requests > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "📦 تثبيت المكتبات..."
    pip3 install -r requirements.txt
fi

# التحقق من وجود config.json
if [ ! -f "config.json" ]; then
    echo "❌ ملف config.json غير موجود!"
    echo "📝 نسخ ملف النموذج..."
    cp config.json.example config.json
    echo "✅ تم إنشاء config.json"
    echo "⚠️  عدل الملف وحط Access Token و Open ID ديالك"
    exit 1
fi

echo "✅ كلشي مزيان!"
echo "🚀 بداية التشغيل..."
echo ""

# تشغيل السكريپت
python3 main.py
