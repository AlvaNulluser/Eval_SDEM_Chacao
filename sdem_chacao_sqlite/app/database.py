import os
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# La base vive junto al proyecto, sin depender del directorio desde donde se ejecute.
# DATABASE_URL permite apuntar a otro archivo (por ejemplo en los tests).
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{PROJECT_ROOT / 'sdem_chacao.db'}"

connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)
    level = Column(Integer, nullable=False)
    failed_attempts = Column(Integer, default=0)
    locked = Column(Boolean, default=False)

class AnalysisRecord(Base):
    __tablename__ = "analysis_history"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    findings = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    user = Column(String(50), nullable=False, index=True)
    action = Column(String(50), nullable=False)
    detail = Column(Text, nullable=False)

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    lat = Column(Float, nullable=False)
    lon = Column(Float, nullable=False)

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            initial_users = [
                ("admin", "Admin#2026", "Administrador", 4),
                ("analista", "Analista#2026", "Analista de seguridad", 3),
                ("auditor", "Auditor#2026", "Auditor", 2),
                ("empleado", "Empleado#2026", "Empleado", 1),
                ("jperez", "Perez#2026", "Empleado", 1),
                ("mgomez", "Gomez#2026", "Analista de seguridad", 3),
            ]
            for uname, pwd, role, lvl in initial_users:
                db.add(User(
                    username=uname,
                    hashed_password=pwd_context.hash(pwd),
                    role=role,
                    level=lvl
                ))
            db.add(Company(name="Aduanas Chacao C.A.", lat=10.4967, lon=-66.8537))
            db.commit()
    finally:
        db.close()
