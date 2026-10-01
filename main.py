"""WebScan - analizador de configuración de seguridad web.
API REST (FastAPI) + SQLite. Docs automáticas en /docs."""
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "scans.db"))
TIMEOUT = 8
MAX_REDIRECTS = 5

app = FastAPI(
    title="WebScan API",
    description="Analiza HTTPS, cabeceras de seguridad, cookies y TLS de una web y guarda el historial.",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


# ---------------------------------------------------------------- base de datos
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                created_at TEXT NOT NULL,
                report TEXT NOT NULL
            )"""
        )


init_db()


# ---------------------------------------------------------------- seguridad (SSRF)
def assert_public_host(host: str):
    """Bloquea localhost, redes privadas, link-local, etc."""
    if not host:
        raise HTTPException(400, "URL sin host válido")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(400, f"No se puede resolver el dominio: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(400, "Dirección interna o no permitida")


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise HTTPException(400, "URL vacía")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise HTTPException(400, "Solo se permiten http y https")
    assert_public_host(p.hostname)
    return raw


# ---------------------------------------------------------------- comprobaciones
def fetch(url: str):
    """GET siguiendo redirecciones a mano, validando cada salto. Devuelve (resp, set_cookies, cadena)."""
    cookies, chain = [], [url]
    session = requests.Session()
    headers = {"User-Agent": "WebScan/1.0 (security-config-check)"}
    for _ in range(MAX_REDIRECTS + 1):
        try:
            resp = session.get(url, headers=headers, timeout=TIMEOUT,
                               allow_redirects=False, stream=True)
        except requests.RequestException as e:
            raise HTTPException(502, f"No se pudo conectar: {type(e).__name__}")
        cookies += resp.raw.headers.getlist("Set-Cookie")
        loc = resp.headers.get("Location")
        if resp.is_redirect and loc:
            url = urljoin(url, loc)
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                raise HTTPException(400, "Redirección a esquema no permitido")
            assert_public_host(p.hostname)
            chain.append(url)
            resp.close()
            continue
        resp.close()
        return resp, cookies, chain
    raise HTTPException(502, "Demasiadas redirecciones")


def finding(ok, title, detail, rec=""):
    return {"ok": ok, "title": title, "detail": detail, "recommendation": "" if ok else rec}


def check_https(final_url, chain):
    ok = urlparse(final_url).scheme == "https"
    f = [finding(ok, "Conexión HTTPS",
                 "La web se sirve por HTTPS." if ok else "La web se sirve sin cifrar (HTTP).",
                 "Activa HTTPS con un certificado (p. ej. Let's Encrypt) y redirige todo el tráfico HTTP.")]
    return {"score": 20 if ok else 0, "max": 20, "findings": f}


HEADER_RULES = [
    ("strict-transport-security", "HSTS", 12,
     "Añade Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "Content-Security-Policy", 12,
     "Define una CSP restrictiva para limitar el origen de scripts y recursos."),
    ("x-frame-options", "X-Frame-Options", 8,
     "Añade X-Frame-Options: DENY (o frame-ancestors en la CSP) contra clickjacking."),
    ("x-content-type-options", "X-Content-Type-Options", 6,
     "Añade X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Referrer-Policy", 6,
     "Añade Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "Permissions-Policy", 6,
     "Añade Permissions-Policy para desactivar APIs del navegador que no uses."),
]


def check_headers(h):
    h = {k.lower(): v for k, v in h.items()}
    score, findings = 0, []
    for key, name, pts, rec in HEADER_RULES:
        present = key in h
        if key == "x-frame-options" and not present:
            present = "frame-ancestors" in h.get("content-security-policy", "").lower()
        if present:
            score += pts
        findings.append(finding(present, name,
                                "Presente." if present else "No está configurada.", rec))
    return {"score": score, "max": 50, "findings": findings}


def check_cookies(set_cookies):
    if not set_cookies:
        return {"score": 15, "max": 15,
                "findings": [finding(True, "Cookies", "La web no establece cookies.")]}
    findings, good, total = [], 0, 0
    for raw in set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0]
        attrs = [p.lower() for p in parts[1:]]
        checks = {
            "Secure": "secure" in attrs,
            "HttpOnly": "httponly" in attrs,
            "SameSite": any(a.startswith("samesite") for a in attrs),
        }
        for flag, ok in checks.items():
            total += 1
            good += ok
            findings.append(finding(ok, f"Cookie «{name}»: {flag}",
                                    "Correcto." if ok else f"Falta el atributo {flag}.",
                                    f"Añade el atributo {flag} a la cookie {name}."))
    return {"score": round(15 * good / total), "max": 15, "findings": findings}


def check_tls(final_url):
    p = urlparse(final_url)
    if p.scheme != "https":
        return {"score": 0, "max": 15,
                "findings": [finding(False, "TLS", "No hay HTTPS, no se puede evaluar TLS.",
                                     "Activa HTTPS con TLS 1.2 o superior.")]}
    host, port = p.hostname, p.port or 443
    ctx = ssl.create_default_context()
    findings, score = [], 0
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                version = s.version()
                cert = s.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"score": 0, "max": 15, "findings": [finding(
            False, "Certificado", f"Certificado no válido: {e.verify_message}",
            "Instala un certificado válido, vigente y emitido para este dominio.")]}
    except (OSError, ssl.SSLError) as e:
        return {"score": 0, "max": 15, "findings": [finding(
            False, "TLS", f"Fallo en el handshake: {type(e).__name__}",
            "Revisa la configuración TLS del servidor.")]}

    pts = {"TLSv1.3": 10, "TLSv1.2": 7}.get(version, 0)
    score += pts
    findings.append(finding(pts >= 7, f"Versión de protocolo: {version}",
                            "Protocolo moderno." if pts >= 7 else "Protocolo obsoleto.",
                            "Deshabilita TLS 1.0/1.1 y habilita TLS 1.2 y 1.3."))
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    cpts = 5 if days > 30 else (2 if days > 0 else 0)
    score += cpts
    findings.append(finding(days > 30, f"Caducidad del certificado: {days} días",
                            "Vigencia suficiente." if days > 30 else "Caduca pronto o ya ha caducado.",
                            "Renueva el certificado; automatiza la renovación (certbot)."))
    return {"score": score, "max": 15, "findings": findings}


def grade_for(score):
    for limit, g in ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (35, "E")):
        if score >= limit:
            return g
    return "F"


def run_scan(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    resp, cookies, chain = fetch(url)
    final = chain[-1]
    cats = {
        "https": check_https(final, chain),
        "headers": check_headers(resp.headers),
        "cookies": check_cookies(cookies),
        "tls": check_tls(final),
    }
    score = sum(c["score"] for c in cats.values())
    return {"url": url, "final_url": final, "redirects": chain, "status_code": resp.status_code,
            "score": score, "grade": grade_for(score), "categories": cats}


# ---------------------------------------------------------------- endpoints
class ScanRequest(BaseModel):
    url: str


def load(scan_id: int):
    with db() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Análisis no encontrado")
    return row


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.post("/scans", summary="Analizar una URL y guardar el resultado")
def create_scan(body: ScanRequest):
    report = run_scan(body.url)
    domain = urlparse(report["url"]).hostname
    with db() as c:
        cur = c.execute(
            "INSERT INTO scans (url, domain, score, grade, created_at, report) VALUES (?,?,?,?,?,?)",
            (report["url"], domain, report["score"], report["grade"],
             datetime.now(timezone.utc).isoformat(timespec="seconds"), json.dumps(report)))
    return {"id": cur.lastrowid, **report}


@app.get("/scans", summary="Historial con filtros por dominio y nota mínima")
def list_scans(domain: Optional[str] = None,
               min_score: int = Query(0, ge=0, le=100),
               limit: int = Query(50, ge=1, le=200)):
    sql, params = "SELECT id,url,domain,score,grade,created_at FROM scans WHERE score>=?", [min_score]
    if domain:
        sql += " AND domain LIKE ?"
        params.append(f"%{domain}%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


@app.get("/scans/{scan_id}", summary="Informe completo de un análisis")
def get_scan(scan_id: int):
    row = load(scan_id)
    return {"id": row["id"], "created_at": row["created_at"], **json.loads(row["report"])}


@app.get("/scans/{scan_id}/recommendations", summary="Solo las mejoras pendientes")
def get_recommendations(scan_id: int):
    row = load(scan_id)
    report = json.loads(row["report"])
    recs = [{"category": cat, "issue": f["title"], "recommendation": f["recommendation"]}
            for cat, data in report["categories"].items()
            for f in data["findings"] if not f["ok"]]
    return {"id": scan_id, "url": report["url"], "grade": report["grade"], "recommendations": recs}


@app.delete("/scans/{scan_id}", summary="Borrar un análisis")
def delete_scan(scan_id: int):
    load(scan_id)
    with db() as c:
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    return {"deleted": scan_id}


@app.get("/stats", summary="Total, nota media y reparto por letra")
def stats():
    with db() as c:
        total, avg = c.execute("SELECT COUNT(*), AVG(score) FROM scans").fetchone()
        dist = {r["grade"]: r["n"] for r in
                c.execute("SELECT grade, COUNT(*) n FROM scans GROUP BY grade")}
    return {"total": total, "average_score": round(avg, 1) if avg else 0,
            "by_grade": {g: dist.get(g, 0) for g in "ABCDEF"}}
