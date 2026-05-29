#!/bin/bash
cd "$(dirname "$0")"

# Installeer Flask als die er nog niet is
if ! python3 -c "import flask" 2>/dev/null; then
  echo "Flask installeren..."
  pip3 install -r requirements.txt
fi

echo ""
echo "  App starten op http://localhost:5000"
echo "  Stop met Ctrl+C"
echo ""
python3 app.py
