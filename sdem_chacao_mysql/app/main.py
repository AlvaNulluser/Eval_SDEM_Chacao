import os
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import re
import jwt

from app.database import SessionLocal, init_db, pwd_context, User, AnalysisRecord, AuditLog, Company

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_SECRET_KEY = "sdem-chacao-dev-key-solo-para-desarrollo-local"
SECRET_KEY = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
ALGORITHM = "HS256"

app = FastAPI(title="SDEM Chacao - MySQL")
init_db()

app.mount("/static", StaticFiles(directory=PROJECT_ROOT / "static"), name="static")

# Matriz de permisos: Empleado=1, Auditor=2 (solo lectura), Analista=3, Administrador=4.
ROLE_LEVELS = {"Administrador": 4, "Analista de seguridad": 3, "Auditor": 2, "Empleado": 1}
ANALYZE_LEVELS = (1, 3, 4)
READ_LEVELS = (2, 3, 4)
COMPANY_LEVELS = (3, 4)
ADMIN_LEVELS = (4,)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(username: str, role: str, level: int):
    expire = datetime.now(timezone.utc) + timedelta(hours=8)
    payload = {"sub": username, "role": role, "level": level, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    token = authorization.split(" ")[1]
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

def ensure_level(current: dict, allowed: tuple, message: str = "Permisos insuficientes para esta acción"):
    if current.get("level") not in allowed:
        raise HTTPException(status_code=403, detail=message)
    return current

class LoginReq(BaseModel):
    username: str
    password: str

class UrlReq(BaseModel):
    url: str

class EmailReq(BaseModel):
    content: str

class NewUserReq(BaseModel):
    username: str
    password: str
    role: str

class CompanyReq(BaseModel):
    name: str
    lat: float
    lon: float

def add_log(db: Session, user: str, action: str, detail: str):
    db.add(AuditLog(
        timestamp=datetime.now(),
        user=user,
        action=action,
        detail=detail
    ))
    db.commit()

def evaluate_url(raw_url: str) -> dict:
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    domain = parsed.netloc.lower()
    full_url = raw_url.lower()
    score = 0
    findings = []

    if parsed.scheme == "http":
        score += 15
        findings.append("Protocolo no seguro (HTTP)")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
        score += 35
        findings.append("Uso de dirección IP en lugar de dominio")
    if "@" in full_url:
        score += 30
        findings.append("Contiene símbolo '@' (redirección encubierta)")
    if "xn--" in domain:
        score += 30
        findings.append("Dominio Punycode (ataque homógrafo)")
    if domain.count(".") > 3:
        score += 20
        findings.append("Subdominios excesivos")
    if any(domain.split(":")[0].endswith(t) for t in (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip")):
        score += 25
        findings.append("TLD de alto riesgo")
    if any(s in domain for s in ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly")):
        score += 20
        findings.append("URL acortada")
    if any(w in full_url for w in ("login", "verify", "update", "secure", "account", "clave", "token", "factura", "aduana")):
        score += 15
        findings.append("Palabras clave de phishing")
    
    brands = ("seniat", "dhl", "maersk", "banesco", "mercantil", "provincial", "bdv", "fedex")
    officials = ("seniat.gob.ve", "dhl.com", "maersk.com", "banesco.com", "mercantilbanco.com")
    for b in brands:
        if b in full_url and not any(domain.endswith(od) for od in officials):
            score += 40
            findings.append(f"Posible suplantación de marca ({b.upper()})")

    if re.search(r"%[0-9a-fA-F]{2}", full_url):
        score += 15
        findings.append("Codificación hexadecimal")
    try:
        port = parsed.port
        if port and port not in (80, 443):
            score += 25
            findings.append(f"Puerto atípico ({port})")
    except ValueError:
        # urlparse lanza ValueError con puertos no numéricos o fuera de rango.
        score += 25
        findings.append("Puerto inválido en la URL")
    if len(full_url) > 75:
        score += 15
        findings.append("Longitud anómala (>75 caracteres)")

    status = "Malicioso" if score >= 55 else ("Sospechoso" if score >= 25 else "Seguro")
    return {
        "url": raw_url,
        "status": status,
        "score": min(score, 100),
        "findings": findings if findings else ["Sin anomalías detectadas"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

@app.get("/")
def serve_frontend():
    return FileResponse(PROJECT_ROOT / "static" / "index.html")

@app.post("/api/login")
def login(data: LoginReq, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    if user.locked:
        raise HTTPException(status_code=403, detail="Cuenta bloqueada tras 3 intentos fallidos.")

    if not pwd_context.verify(data.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            user.locked = True
            db.commit()
            add_log(db, user.username, "BLOQUEO", "Cuenta bloqueada por 3 intentos fallidos")
            raise HTTPException(status_code=403, detail="Cuenta bloqueada tras 3 intentos fallidos.")
        db.commit()
        raise HTTPException(status_code=401, detail=f"Contraseña incorrecta. Intentos restantes: {3 - user.failed_attempts}")

    user.failed_attempts = 0
    db.commit()
    add_log(db, user.username, "LOGIN", f"Inicio de sesión ({user.role})")
    token = create_token(user.username, user.role, user.level)
    return {"token": token, "username": user.username, "role": user.role, "level": user.level}

@app.post("/api/analyze-url")
def analyze_url(data: UrlReq, db: Session = Depends(get_db), current=Depends(get_current_user)):
    ensure_level(current, ANALYZE_LEVELS)
    res = evaluate_url(data.url)
    db.add(AnalysisRecord(
        url=res["url"], status=res["status"], score=res["score"],
        findings=", ".join(res["findings"]), timestamp=datetime.now()
    ))
    db.commit()
    add_log(db, current["sub"], "ANÁLISIS URL", f"{res['url']} -> {res['status']}")
    return res

@app.post("/api/analyze-email")
def analyze_email(data: EmailReq, db: Session = Depends(get_db), current=Depends(get_current_user)):
    ensure_level(current, ANALYZE_LEVELS)
    # Se recorta la puntuación final (coma, punto, paréntesis...) y se deduplica
    # preservando el orden de aparición en el correo.
    found = [u.rstrip(".,;:!?)]") for u in re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', data.content)]
    urls = list(dict.fromkeys(u for u in found if u))
    results = []
    for u in urls:
        res = evaluate_url(u)
        db.add(AnalysisRecord(
            url=res["url"], status=res["status"], score=res["score"],
            findings=", ".join(res["findings"]), timestamp=datetime.now()
        ))
        results.append(res)
    db.commit()
    add_log(db, current["sub"], "ANÁLISIS CORREO", f"{len(results)} enlaces analizados")
    return {"extracted_count": len(results), "results": results}

@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), current=Depends(get_current_user)):
    ensure_level(current, READ_LEVELS, "El panel está disponible para Auditor, Analista y Administrador")
    records = db.query(AnalysisRecord).order_by(AnalysisRecord.id.desc()).all()
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).all()
    companies = db.query(Company).all()

    def fmt(value):
        return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""

    return {
        "metrics": {
            "total": len(records),
            "seguros": sum(1 for r in records if r.status == "Seguro"),
            "sospechosos": sum(1 for r in records if r.status == "Sospechoso"),
            "maliciosos": sum(1 for r in records if r.status == "Malicioso"),
        },
        "recent": [{"url": r.url, "status": r.status, "timestamp": fmt(r.timestamp)} for r in records[:10]],
        "logs": [{"timestamp": fmt(l.timestamp), "user": l.user, "action": l.action, "detail": l.detail} for l in logs],
        "companies": [{"name": c.name, "lat": c.lat, "lon": c.lon} for c in companies]
    }

@app.post("/api/users")
def create_user(data: NewUserReq, db: Session = Depends(get_db), current=Depends(get_current_user)):
    ensure_level(current, ADMIN_LEVELS, "Solo el Administrador puede crear usuarios")
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$", data.password):
        raise HTTPException(status_code=400, detail="Contraseña débil (mín. 8 chars, mayúscula, minúscula, número y símbolo)")

    db.add(User(
        username=data.username,
        hashed_password=pwd_context.hash(data.password),
        role=data.role,
        level=ROLE_LEVELS.get(data.role, 1)
    ))
    db.commit()
    add_log(db, current["sub"], "CREAR USUARIO", f"Usuario '{data.username}' ({data.role})")
    return {"message": "Usuario creado con éxito"}

@app.post("/api/companies")
def add_company(data: CompanyReq, db: Session = Depends(get_db), current=Depends(get_current_user)):
    ensure_level(current, COMPANY_LEVELS)
    db.add(Company(name=data.name, lat=data.lat, lon=data.lon))
    db.commit()
    add_log(db, current["sub"], "GEOLOCALIZACIÓN", f"Empresa '{data.name}' ({data.lat}, {data.lon})")
    return {"message": "Empresa registrada"}
