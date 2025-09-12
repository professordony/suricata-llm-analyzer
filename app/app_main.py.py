#!/usr/bin/env python3\
"""\
Suricata LLM Analyzer - FastAPI Application\
Versão Profissional para análise de logs IDS/IPS com LLM local\
"""

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks\
from fastapi.templating import Jinja2Templates\
from fastapi.staticfiles import StaticFiles\
from fastapi.responses import HTMLResponse, JSONResponse\
from sqlalchemy.orm import Session\
import json\
import asyncio\
from datetime import datetime\
from typing import List, Dict, Any\
import logging

from .database import SessionLocal, engine, Base\
from .models import LogEntry, LLMAnalysis\
from .llm_service import LLMService

# Configurar logging

logging.basicConfig(\
[level=logging.INFO](http://level=logging.INFO),\
format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',\
handlers=\[\
logging.FileHandler('logs/app.log'),\
logging.StreamHandler()\
\]\
)\
logger = logging.getLogger(**name**)

# Criar tabelas

Base.metadata.create_all(bind=engine)

# Inicializar FastAPI

app = FastAPI(\
title="Suricata LLM Analyzer",\
description="Sistema profissional de análise de logs IDS/IPS com IA local",\
version="1.0.0"\
)

# Templates

templates = Jinja2Templates(directory="app/templates")

# Inicializar serviço LLM

llm_service = LLMService()

def get_db():\
"""Dependency para obter sessão do banco"""\
db = SessionLocal()\
try:\
yield db\
finally:\
db.close()

@app.on_event("startup")\
async def startup_event():\
"""Inicialização da aplicação"""\
[logger.info](http://logger.info)("🚀 Iniciando Suricata LLM Analyzer...")

```
# Verificar se Ollama está rodando
if not await llm_service.check_ollama_health():
    logger.error("❌ Ollama não está rodando! Execute: ollama serve")
    raise HTTPException(status_code=500, detail="Ollama service not available")

logger.info("✅ Aplicação iniciada com sucesso!")
```

@app.get("/", response_class=HTMLResponse)\
async def dashboard(request: Request):\
"""Dashboard principal"""\
db = SessionLocal()\
try:\
# Buscar últimos 50 logs\
recent_logs = db.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(50).all()

```
    # Estatísticas básicas
    total_logs = db.query(LogEntry).count()
    high_severity = db.query(LLMAnalysis).filter(LLMAnalysis.criticidade == "alta").count()
    
    stats = {
        "total_logs": total_logs,
        "high_severity": high_severity,
        "recent_count": len(recent_logs)
    }
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "logs": recent_logs,
        "stats": stats
    })
finally:
    db.close()
```

@app.post("/api/analyze_log")\
async def analyze_log(log_data: Dict\[Any, Any\], background_tasks: BackgroundTasks):\
"""\
Endpoint para receber e analisar logs do Suricata\
"""\
try:\
[logger.info](http://logger.info)(f"📥 Recebido log: {log_data.get('event_type', 'unknown')}")

```
    # Processar em background para não bloquear
    background_tasks.add_task(process_log_async, log_data)
    
    return {"status": "accepted", "message": "Log sendo processado"}
    
except Exception as e:
    logger.error(f"❌ Erro ao processar log: {str(e)}")
    raise HTTPException(status_code=500, detail=str(e))
```

async def process_log_async(log_data: Dict\[Any, Any\]):\
"""Processar log de forma assíncrona"""\
db = SessionLocal()\
try:\
# Salvar log bruto\
log_entry = LogEntry(\
timestamp=datetime.now(),\
event_type=log_data.get('event_type', 'unknown'),\
src_ip=log_data.get('src_ip', ''),\
dest_ip=log_data.get('dest_ip', ''),\
src_port=log_data.get('src_port', 0),\
dest_port=log_data.get('dest_port', 0),\
protocol=log_data.get('proto', ''),\
raw_log=json.dumps(log_data),\
severity=log_data.get('severity', 3)\
)\
db.add(log_entry)\
db.commit()\
db.refresh(log_entry)

```
    # Analisar com LLM
    logger.info("🤖 Enviando para análise LLM...")
    analysis_result = await llm_service.analyze_log(log_data)
    
    if analysis_result:
        # Salvar análise
        llm_analysis = LLMAnalysis(
            log_id=log_entry.id,
            resumo=analysis_result.get('resumo', ''),
            tipo_ataque=analysis_result.get('tipo_ataque', ''),
            criticidade=analysis_result.get('criticidade', 'baixa'),
            acao_recomendada=analysis_result.get('acao_recomendada', ''),
            raw_response=json.dumps(analysis_result)
        )
        db.add(llm_analysis)
        db.commit()
        
        logger.info(f"✅ Log analisado: {analysis_result.get('tipo_ataque')} - {analysis_result.get('criticidade')}")
    
except Exception as e:
    logger.error(f"❌ Erro no processamento assíncrono: {str(e)}")
    db.rollback()
finally:
    db.close()
```

@app.get("/api/logs")\
async def get_logs(limit: int = 50, severity: str = None):\
"""API para buscar logs"""\
db = SessionLocal()\
try:\
query = db.query(LogEntry).order_by(LogEntry.timestamp.desc())

```
    if severity:
        query = query.join(LLMAnalysis).filter(LLMAnalysis.criticidade == severity)
    
    logs = query.limit(limit).all()
    
    result = []
    for log in logs:
        log_dict = {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "event_type": log.event_type,
            "src_ip": log.src_ip,
            "dest_ip": log.dest_ip,
            "src_port": log.src_port,
            "dest_port": log.dest_port,
            "protocol": log.protocol,
            "severity": log.severity
        }
        
        # Adicionar análise se existir
        if log.analysis:
            log_dict["analysis"] = {
                "resumo": log.analysis[0].resumo,
                "tipo_ataque": log.analysis[0].tipo_ataque,
                "criticidade": log.analysis[0].criticidade,
                "acao_recomendada": log.analysis[0].acao_recomendada
            }
        
        result.append(log_dict)
    
    return {"logs": result}
    
finally:
    db.close()
```

@app.get("/api/stats")\
async def get_stats():\
"""Estatísticas da aplicação"""\
db = SessionLocal()\
try:\
stats = {\
"total_logs": db.query(LogEntry).count(),\
"alta_criticidade": db.query(LLMAnalysis).filter(LLMAnalysis.criticidade == "alta").count(),\
"media_criticidade": db.query(LLMAnalysis).filter(LLMAnalysis.criticidade == "média").count(),\
"baixa_criticidade": db.query(LLMAnalysis).filter(LLMAnalysis.criticidade == "baixa").count(),\
}

```
    # Top tipos de ataque
    top_attacks = db.query(LLMAnalysis.tipo_ataque, db.func.count(LLMAnalysis.tipo_ataque).label('count'))\
                   .group_by(LLMAnalysis.tipo_ataque)\
                   .order_by(db.func.count(LLMAnalysis.tipo_ataque).desc())\
                   .limit(10).all()
    
    stats["top_attacks"] = [{"tipo": attack[0], "count": attack[1]} for attack in top_attacks]
    
    return stats
    
finally:
    db.close()
```

@app.get("/health")\
async def health_check():\
"""Health check da aplicação"""\
ollama_status = await llm_service.check_ollama_health()

```
return {
    "status": "healthy" if ollama_status else "degraded",
    "ollama": "online" if ollama_status else "offline",
    "timestamp": datetime.now().isoformat()
}
```

if **name** == "**main**":\
import uvicorn\
uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)