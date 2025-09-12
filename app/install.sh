#!/bin/bash
set -e

echo "🚀 Instalando dependências do Suricata LLM Analyzer..."

# Pacotes básicos
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    git curl wget unzip build-essential

# Instalar Suricata
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install -y suricata

# Instalar Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull gemma2:2b

# Criar e ativar venv
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Instalação concluída"