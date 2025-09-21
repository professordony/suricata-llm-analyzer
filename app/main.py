import logging
from fastapi import FastAPI, Request, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
import json

from .database import SessionLocal, engine, Base
from .models import LogEntry, LLMAnalysis
from .llm_service import LLMService

# Configuração de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("app.main")

# Inicialização do FastAPI
app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

# Criar tabelas no banco
Base.metadata.create_all(bind=engine)

# Instância do serviço LLM
llm_service = LLMService()

# Dependência: Sessão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================================
# Rota principal (dashboard)
# ================================
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    logs = db.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(50).all()

    # Converter raw_log para dict se for string
    for l in logs:
        try:
            if isinstance(l.raw_log, str):
                l.raw_log = json.loads(l.raw_log)
        except Exception:
            l.raw_log = {}

    context = {
        "request": request,
        "logs": logs,
        "total_logs": db.query(LogEntry).count(),
        "logs_alta": db.query(LLMAnalysis).filter(LLMAnalysis.criticidade == "alta").count(),
        "logs_recentes": len(logs)
    }
    return templates.TemplateResponse("dashboard.html", context)

# ================================
# API: Receber logs para análise
# ================================
@app.post("/api/analyze_log")
async def analyze_log(log_data: dict, db: Session = Depends(get_db)):
    logger.info("🤖 Analisando log com LLM...")

    # Salvar log cru
    log_entry = LogEntry(
        event_type=log_data.get("event_type", "N/A"),
        src_ip=log_data.get("src_ip"),
        src_port=log_data.get("src_port"),
        dest_ip=log_data.get("dest_ip"),
        dest_port=log_data.get("dest_port"),
        proto=log_data.get("proto"),
        signature=log_data.get("alert", {}).get("signature", log_data.get("signature")),
        raw_log=json.dumps(log_data, ensure_ascii=False)
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # Chamar IA
    analysis_result = await llm_service.analyze_log(log_data)

    if analysis_result:
        analysis = LLMAnalysis(
            log_id=log_entry.id,
            tipo_ataque=analysis_result.get("tipo_ataque"),
            resumo=analysis_result.get("resumo"),
            criticidade=analysis_result.get("criticidade"),
            acao_recomendada=analysis_result.get("acao_recomendada"),
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
        logger.info(f"✅ Análise registrada: {analysis.tipo_ataque} - Criticidade {analysis.criticidade}")
    else:
        logger.warning("⚠️ Nenhuma análise realizada.")

    return JSONResponse(content={"status": "ok"})
