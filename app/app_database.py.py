#!/usr/bin/env python3
"""
Configuração do banco de dados SQLite
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Criar diretório de dados se não existir
os.makedirs("data", exist_ok=True)

# URL do banco SQLite
SQLALCHEMY_DATABASE_URL = "sqlite:///./data/suricata_analyzer.db"

# Engine do SQLAlchemy
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}  # Necessário para SQLite
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para os modelos
Base = declarative_base()