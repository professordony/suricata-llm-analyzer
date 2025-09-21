#!/usr/bin/env python3
"""
Modelos SQLAlchemy para o banco de dados
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base  # use o Base do database, não crie outro

#Base = declarative_base()

class LogEntry(Base):
    """Modelo para armazenar logs brutos do Suricata"""
    __tablename__ = "log_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(100), index=True)
    src_ip = Column(String(45), index=True)  # IPv6 support
    dest_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    raw_log = Column(Text)  # JSON completo do log
    severity = Column(Integer, default=3)  # 1=baixa, 2=média, 3=alta
    
    # Relacionamento com análises
    analysis = relationship("LLMAnalysis", back_populates="log_entry")

class LLMAnalysis(Base):
    """Modelo para armazenar análises da LLM"""
    __tablename__ = "llm_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("log_entries.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Campos estruturados da análise
    resumo = Column(Text)
    tipo_ataque = Column(String(100), index=True)
    criticidade = Column(String(20), index=True)  # baixa, média, alta
    acao_recomendada = Column(Text)
    
    # Resposta bruta da LLM para auditoria
    raw_response = Column(Text)
    
    # Relacionamento
    log_entry = relationship("LogEntry", back_populates="analysis")
