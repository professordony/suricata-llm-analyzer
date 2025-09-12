#!/bin/bash

echo "🚀 Iniciando Suricata LLM Analyzer..."

source venv/bin/activate

# Verifica Ollama
if ! pgrep -x "ollama" > /dev/null; then
    echo "Iniciando serviço Ollama..."
    ollama serve &
    sleep 5
fi

# Inicia Suricata
if ! systemctl is-active --quiet suricata; then
    echo "Iniciando Suricata..."
    sudo systemctl start suricata
fi

# Inicia FastAPI
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload