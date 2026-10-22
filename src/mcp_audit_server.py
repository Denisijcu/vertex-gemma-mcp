from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("Vertex-Audit-MCP")

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}

def validate_target(url: str) -> None:
    """Hardening: Bloquea escaneos no autorizados fuera del entorno local o laboratorio."""
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Target bloqueado por política de seguridad: {parsed.hostname}")

@mcp.tool()
def audit_security_headers(url: str) -> dict:
    """Audita cabeceras de seguridad defensivas (HSTS, CSP, X-Frame, CORS) de un endpoint HTTP."""
    validate_target(url)
    with httpx.Client(timeout=5.0, verify=False) as client:
        r = client.get(url)
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {
            "url": url,
            "status_code": r.status_code,
            "missing_hsts": "strict-transport-security" not in headers,
            "missing_csp": "content-security-policy" not in headers,
            "missing_xframe": "x-frame-options" not in headers,
            "cors_wildcard": headers.get("access-control-allow-origin") == "*",
            "server_banner": headers.get("server", "hidden")
        }

@mcp.tool()
def inspect_openapi_routes(openapi_json_url: str) -> list:
    """Extrae rutas y métodos HTTP de un esquema swagger/openapi.json para análisis de superficie."""
    validate_target(openapi_json_url)
    with httpx.Client(timeout=5.0) as client:
        spec = client.get(openapi_json_url).json()
        return [
            {"path": path, "methods": list(methods.keys())}
            for path, methods in list(spec.get("paths", {}).items())[:15]
        ]

if __name__ == "__main__":
    mcp.run()