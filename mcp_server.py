"""Servidor MCP: expone la API de WebScan como herramientas invocables desde Claude.
Requiere que la API esté en marcha (uvicorn main:app). Variable WEBSCAN_URL para cambiar la dirección."""
import os

import requests
from mcp.server.fastmcp import FastMCP

BASE = os.environ.get("WEBSCAN_URL", "http://127.0.0.1:8000")
mcp = FastMCP("webscan")


def call(method, path, **kw):
    r = requests.request(method, BASE + path, timeout=30, **kw)
    if r.status_code >= 400:
        try:
            return {"error": r.json().get("detail", r.text)}
        except ValueError:
            return {"error": r.text}
    return r.json()


@mcp.tool()
def analyze_url(url: str) -> dict:
    """Analiza HTTPS, cabeceras, cookies y TLS de una web. Devuelve nota, puntuación y hallazgos."""
    return call("POST", "/scans", json={"url": url})


@mcp.tool()
def list_scans(domain: str = "", min_score: int = 0) -> list | dict:
    """Lista el historial de análisis, filtrable por dominio y puntuación mínima."""
    params = {"min_score": min_score}
    if domain:
        params["domain"] = domain
    return call("GET", "/scans", params=params)


@mcp.tool()
def get_scan(scan_id: int) -> dict:
    """Devuelve el informe completo de un análisis."""
    return call("GET", f"/scans/{scan_id}")


@mcp.tool()
def get_recommendations(scan_id: int) -> dict:
    """Devuelve solo las mejoras pendientes de un análisis."""
    return call("GET", f"/scans/{scan_id}/recommendations")


@mcp.tool()
def delete_scan(scan_id: int) -> dict:
    """Borra un análisis del historial."""
    return call("DELETE", f"/scans/{scan_id}")


@mcp.tool()
def get_stats() -> dict:
    """Total de análisis, nota media y reparto por letra."""
    return call("GET", "/stats")


if __name__ == "__main__":
    mcp.run()
