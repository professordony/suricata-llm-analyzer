#!/usr/bin/env python3
"""
Serviço para integração com LLM local (Ollama)
"""

import httpx
import json
import logging
from typing import Dict, Any, Optional
import asyncio

logger = logging.getLogger(__name__)

class LLMService:
    """Serviço para comunicação com Ollama"""
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "gemma2:2b"):
        self.ollama_url = ollama_url
        self.model = model
        self.client = httpx.AsyncClient(timeout=30.0)
        
        # Template do prompt profissional
        self.system_prompt = """Você é um analista SOC especialista em segurança cibernética.
Dado um log de alerta do IDS Suricata, você deve analisar e responder APENAS em formato JSON válido.

Sua resposta deve seguir exatamente este formato:
{
  "resumo": "Descrição concisa do evento em até 2 linhas",
  "tipo_ataque": "Tipo específico do ataque (ex: port_scan, brute_force, sql_injection, etc)",
  "criticidade": "baixa, média ou alta",
  "acao_recomendada": "Ação prática específica para o SOC"
}

IMPORTANTE: Responda APENAS com o JSON, sem texto adicional."""

    async def check_ollama_health(self) -> bool:
        """Verificar se Ollama está rodando"""
        try:
            response = await self.client.get(f"{self.ollama_url}/api/tags")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False

    async def analyze_log(self, log_data: Dict[Any, Any]) -> Optional[Dict[str, str]]:
        """
        Analisar log com LLM
        """
        try:
            # Preparar contexto do log
            log_context = self._prepare_log_context(log_data)
            
            # Prompt completo
            full_prompt = f"{self.system_prompt}\n\nLog para análise:\n{log_context}"
            
            # Payload para Ollama
            payload = {
                "model": self.model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Baixa criatividade para análise técnica
                    "top_p": 0.9,
                    "num_predict": 200   # Limitar tokens para resposta concisa
                }
            }
            
            logger.info(f"🤖 Enviando para LLM: {self.model}")
            
            # Fazer requisição
            response = await self.client.post(
                f"{self.ollama_url}/api/generate",
                json=payload
            )
            
            if response.status_code != 200:
                logger.error(f"Ollama API error: {response.status_code}")
                return None
            
            result = response.json()
            llm_response = result.get("response", "").strip()
            
            logger.info(f"📤 Resposta LLM: {llm_response[:100]}...")
            
            # Parse da resposta JSON
            try:
                analysis = json.loads(llm_response)
                
                # Validar campos obrigatórios
                required_fields = ["resumo", "tipo_ataque", "criticidade", "acao_recomendada"]
                if all(field in analysis for field in required_fields):
                    return analysis
                else:
                    logger.warning("Resposta LLM incompleta, usando fallback")
                    return self._fallback_analysis(log_data)
                    
            except json.JSONDecodeError:
                logger.warning("Resposta LLM não é JSON válido, usando fallback")
                return self._fallback_analysis(log_data)
                
        except Exception as e:
            logger.error(f"Erro na análise LLM: {str(e)}")
            return self._fallback_analysis(log_data)

    def _prepare_log_context(self, log_data: Dict[Any, Any]) -> str:
        """Preparar contexto estruturado do log"""
        context_parts = []
        
        # Informações básicas
        if "event_type" in log_data:
            context_parts.append(f"Tipo de evento: {log_data['event_type']}")
        
        if "src_ip" in log_data:
            context_parts.append(f"IP origem: {log_data['src_ip']}")
            
        if "dest_ip" in log_data:
            context_parts.append(f"IP destino: {log_data['dest_ip']}")
            
        if "src_port" in log_data:
            context_parts.append(f"Porta origem: {log_data['src_port']}")
            
        if "dest_port" in log_data:
            context_parts.append(f"Porta destino: {log_data['dest_port']}")
            
        if "proto" in log_data:
            context_parts.append(f"Protocolo: {log_data['proto']}")
        
        # Informações específicas do alerta
        if "alert" in log_data:
            alert = log_data["alert"]
            if "signature" in alert:
                context_parts.append(f"Assinatura: {alert['signature']}")
            if "category" in alert:
                context_parts.append(f"Categoria: {alert['category']}")
            if "severity" in alert:
                context_parts.append(f"Severidade: {alert['severity']}")
        
        # Payload se disponível (limitado)
        if "payload_printable" in log_data:
            payload = log_data["payload_printable"][:200]  # Limitar tamanho
            context_parts.append(f"Payload: {payload}")
        
        return "\n".join(context_parts)

    def _fallback_analysis(self, log_data: Dict[Any, Any]) -> Dict[str, str]:
        """Análise de fallback quando LLM falha"""
        event_type = log_data.get("event_type", "unknown")
        src_ip = log_data.get("src_ip", "unknown")
        dest_port = log_data.get("dest_port", "unknown")
        
        # Análise básica baseada em regras
        if event_type == "alert":
            alert = log_data.get("alert", {})
            signature = alert.get("signature", "").lower()
            
            if "scan" in signature or "probe" in signature:
                return {
                    "resumo": f"Possível port scan detectado de {src_ip}",
                    "tipo_ataque": "port_scan",
                    "criticidade": "média",
                    "acao_recomendada": "Monitorar IP origem e considerar bloqueio temporário"
                }
            elif "brute" in signature or "force" in signature:
                return {
                    "resumo": f"Tentativa de força bruta detectada de {src_ip}",
                    "tipo_ataque": "brute_force",
                    "criticidade": "alta",
                    "acao_recomendada": "Bloquear IP imediatamente e verificar logs de autenticação"
                }
            elif "sql" in signature:
                return {
                    "resumo": f"Possível SQL injection de {src_ip}",
                    "tipo_ataque": "sql_injection",
                    "criticidade": "alta",
                    "acao_recomendada": "Verificar aplicação web e bloquear IP"
                }
        
        # Fallback genérico
        return {
            "resumo": f"Evento de segurança detectado: {event_type} de {src_ip}",
            "tipo_ataque": event_type,
            "criticidade": "média",
            "acao_recomendada": "Investigar evento e tomar ação conforme política de segurança"
        }

    async def close(self):
        """Fechar cliente HTTP"""
        await self.client.aclose()