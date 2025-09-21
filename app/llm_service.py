import httpx
import json
import logging
import re

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """
Você é um analista SOC (Blue Team). Analise o seguinte alerta do Suricata IDS:

{log}

Responda apenas em formato JSON válido, com os campos:
{{
  "tipo_ataque": "resuma a ameaça detectada (ex: SSH brute force, SQL Injection, Port scan, XSS, etc.)",
  "resumo": "descrição clara: {alert.signature ou signature} de {src_ip} para {dest_ip}:{dest_port} via {proto}",
  "criticidade": "baixa|média|alta (baseada no risco do ataque, não apenas ICMP ruido)",
  "acao_recomendada": "ações práticas sugeridas (ex: bloquear IP, revisar regra de firewall, investigar origem, monitorar logs adicionais)"
}}

⚠️ Importante:
- NÃO inclua ```json nem texto fora do objeto JSON.
- Responda SOMENTE o objeto JSON puro.
- Seja objetivo e técnico, mas completo.
"""

def extract_json(content: str) -> dict:
    """Extrai JSON válido da saída do LLM, limpando blocos markdown."""
    try:
        content = content.replace("```json", "").replace("```", "").strip()
        match = re.search(r"\{.*\}", content, re.S)
        if match:
            return json.loads(match.group(0))
    except Exception as e:
        logger.warning(f"⚠️ Erro ao parsear JSON: {e} | Conteúdo bruto: {content[:200]}")
    return None


class LLMService:
    def __init__(self):
        self.base_url = "http://localhost:11434/api/generate"
        self.model = "gemma3:270m"

    async def check_ollama_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get("http://localhost:11434/api/tags")
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Erro conectando ao Ollama: {e}")
            return False

    async def analyze_log(self, log_data: dict):
        """Analisa logs do Suricata ou alertas agregados."""
        try:
            # detectar assinatura do alerta
            signature = None
            if "alert" in log_data and "signature" in log_data["alert"]:
                signature = log_data["alert"]["signature"]
            elif "signature" in log_data:
                signature = log_data["signature"]
            else:
                signature = "desconhecido"

            # ignorar ICMP trivial
            if signature.lower().startswith("icmp"):
                return {
                    "tipo_ataque": "ICMP Echo (ignorado)",
                    "resumo": f"Ignorado alerta ICMP de {log_data.get('src_ip')} -> {log_data.get('dest_ip')}",
                    "criticidade": "baixa",
                    "acao_recomendada": "Sem ação (ICMP comum)"
                }

            # extrair campos relevantes
            log_highlight = {
                "alert.signature": signature,
                "src_ip": log_data.get("src_ip"),
                "src_port": log_data.get("src_port"),
                "dest_ip": log_data.get("dest_ip"),
                "dest_port": log_data.get("dest_port"),
                "proto": log_data.get("proto"),
            }

            log_str = json.dumps(log_highlight, indent=2, ensure_ascii=False)
            prompt = PROMPT_TEMPLATE.format(log=log_str)

            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }

            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(self.base_url, json=payload)

            if resp.status_code != 200:
                logger.error(f"Ollama API error {resp.status_code}: {resp.text}")
                return None

            raw = resp.json()
            content = raw.get("response", "").strip()

            # tenta extrair JSON
            analysis = extract_json(content)

            if not analysis:
                logger.warning("⚠️ LLM não retornou JSON válido. Usando fallback simples.")
                analysis = {
                    "tipo_ataque": signature,
                    "resumo": f"Detectado {signature} de {log_highlight['src_ip']} "
                              f"para {log_highlight['dest_ip']}:{log_highlight.get('dest_port','')} "
                              f"via {log_highlight.get('proto','')}",
                    "criticidade": "média",
                    "acao_recomendada": "Investigar manualmente este log"
                }

            return analysis

        except Exception as e:
            logger.error(f"❌ Erro em analyze_log: {e}. Usando fallback crítico.")
            return {
                "tipo_ataque": "Erro na análise LLM",
                "resumo": f"Falha ao processar log: {str(e)}",
                "criticidade": "média",
                "acao_recomendada": "Verificar configuração do sistema"
            }
