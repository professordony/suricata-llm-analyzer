
🛡️ Suricata LLM Analyzer 

Sistema  de análise de logs IDS/IPS com IA local para detecção e análise de ameaças cibernéticas.

🎯 Características

IA Local: Análise com LLM rodando 100% on-premise (sem envio de dados para nuvem)

Tempo Real: Monitoramento contínuo dos logs do Suricata

Dashboard Web: Interface profissional para visualização e análise

Análise Inteligente: Classificação automática de severidade e recomendações

API REST: Endpoints para integração com outras ferramentas

Armazenamento Local: SQLite para logs e análises

🏗️ Arquitetura
Suricata IDS/IPS → EVE JSON → Monitor Python → FastAPI → LLM (Ollama) → Dashboard
                                    ↓
                              SQLite Database

🚀 Instalação Rápida (Ubuntu)
# 1. Baixar e executar script de instalação
curl -fsSL https://raw.githubusercontent.com/suricata-llm-analyzer
/install.sh | bash

# 2. Entrar no diretório
cd ~/suricata-llm-analyzer

# 3. Iniciar sistema
./start.sh

📋 Instalação Manual
Pré-requisitos

Ubuntu 20.04+ (ou Debian 11+)

Python 3.8+

4GB RAM mínimo (16GB recomendado)

50GB espaço livre

Passo a Passo

Instalar Suricata

sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata

Instalar Ollama

curl -fsSL https://ollama.ai/install.sh | sh

ollama pull gemma2:2b

Configurar Projeto
git clone https://github.com/professordony/suricata-llm-analyze
cd suricata-llm-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Configurar Suricata
# Habilitar EVE JSON output
sudo nano /etc/suricata/suricata.yaml
# Descomentar seção eve-log

Iniciar Sistema
./start.sh

🖥️ Uso
Dashboard Web

Acesse: http://localhost:8000

API Endpoints

GET / - Dashboard principal

POST /api/analyze_log - Analisar log individual

GET /api/logs - Buscar logs

GET /api/stats - Estatísticas

GET /health - Status do sistema

Exemplo de Uso da API
# Enviar log para análise
curl -X POST http://localhost:8000/api/analyze_log \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "alert",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "dest_port": 22,
    "alert": {
      "signature": "SSH Brute Force Attempt",
      "severity": 2
    }
  }'

🧪 Testes
Gerar Logs de Teste
# Port scan (gera alertas)
nmap -sS localhost

# SSH brute force simulado
hydra -l admin -P passwords.txt ssh://localhost

# Ping (ICMP)
ping -c 5 localhost

📊 Funcionalidades
Análise Automática

Classificação de Severidade: Baixa, Média, Alta

Identificação de Ataques: Port scan, brute force, SQL injection, etc.

Recomendações: Ações específicas para cada tipo de ameaça

Correlação: Análise contextual de múltiplos eventos

Dashboard

Estatísticas em Tempo Real: Contadores e métricas

Timeline de Eventos: Visualização cronológica

Filtros: Por severidade, tipo de ataque, IP

Auto-refresh: Atualização automática a cada 30s

Segurança

Dados Locais: Nenhum dado sai do servidor

Logs Auditáveis: Todas as análises são registradas

Acesso Controlado: Autenticação (futuro)

🔧 Configuração
Arquivo de Configuração
# config/app_config.py
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "gemma2:2b"  # ou "mistral:7b", "llama3:8b"
DATABASE_URL = "sqlite:///./data/suricata_analyzer.db"
LOG_LEVEL = "INFO"

Modelos LLM Suportados

gemma2:2b (padrão - leve)

mistral:7b (mais preciso)

llama3:8b (mais avançado)

📈 Expansão Futura
Roadmap

Integração com SIEM (Wazuh, ELK)

SOAR com Shuffle/TheHive

Threat Intelligence (MISP)

DFIR com DFIR-IRIS

Machine Learning para detecção de anomalias

Dashboards avançados (Grafana)

Alertas por email/Slack

Resposta automática (firewall)

Integrações Planejadas
Suricata → FastAPI → [SIEM] → [SOAR] → [TI Feeds] → [DFIR]
                        ↓        ↓         ↓         ↓
                     Wazuh   Shuffle    MISP    DFIR-IRIS

🐛 Troubleshooting
Problemas Comuns

Ollama não responde

# Verificar status
systemctl status ollama
# Reiniciar
sudo systemctl restart ollama


Suricata não gera logs

# Verificar configuração
sudo suricata-update
sudo systemctl restart suricata
# Verificar logs
tail -f /var/log/suricata/eve.json


Permissões de arquivo

# Adicionar usuário ao grupo suricata
sudo usermod -a -G suricata $USER
# Fazer logout/login

📝 Logs

Aplicação: logs/app.log

Suricata: /var/log/suricata/eve.json

Sistema: journalctl -u suricata

🤝 Contribuição

Fork o projeto

Crie uma branch (git checkout -b feature/nova-funcionalidade)

Commit suas mudanças (git commit -am 'Adiciona nova funcionalidade')

Push para a branch (git push origin feature/nova-funcionalidade)

Abra um Pull Request

📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para detalhes.

🆘 Suporte

Issues: Abra uma issue no GitHub

Documentação: Wiki do projeto

Comunidade: Discord/Telegram (em breve)

Desenvolvido com ❤️ para a comunidade de cybersecurity
