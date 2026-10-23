from urllib.parse import urlparse
from mcp.server.mcpserver import MCPServer
import httpx
import re

mcp = MCPServer("Vertex-Audit-MCP")

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
    try:
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
    except Exception as e:
        return {"error": f"Fallo al conectar con el objetivo: {str(e)}"}

@mcp.tool()
def inspect_openapi_routes(openapi_json_url: str) -> list | dict:
    """Extrae rutas y métodos HTTP de un esquema swagger/openapi.json para análisis de superficie."""
    validate_target(openapi_json_url)
    try:
        with httpx.Client(timeout=5.0, verify=False) as client:
            r = client.get(openapi_json_url)
            spec = r.json()
            paths = spec.get("paths", {})
            return [
                {"path": path, "methods": list(methods.keys())}
                for path, methods in list(paths.items()[:15])
            ]
    except Exception as e:
        return {"error": f"No se pudo parsear el esquema OpenAPI: {str(e)}"}

@mcp.tool()
def static_code_security_scan(source_code_snippet: str) -> list:
    """Analiza un fragmento de código fuente en busca de patrones de vulnerabilidades comunes (OWASP Top 10)."""
    findings = []
    
    # Patrones de riesgo estáticos comunes
    patterns = [
        (r"\beval\s*\(", "Uso de eval() detectado: Riesgo crítico de ejecución remota de código (RCE)."),
        (r"\bexec\s*\(", "Uso de exec() detectado: Posible inyección de comandos o manipulación de entorno."),
        (r"subprocess\..*shell\s*=\s*True", "Uso de subprocess con shell=True: Alto riesgo de Command Injection."),
        (r"cursor\.execute\s*\(.+%.+\)", "Posible Inyección SQL: Concatenación directa de variables en consultas SQL."),
        (r"pickle\.loads?\s*\(", "Uso de pickle detectado: Deserialización insegura de objetos.")
    ]
    
    for pattern, description in patterns:
        if re.search(pattern, source_code_snippet):
            findings.append({"pattern": pattern, "warning": description})
            
    if not findings:
        return [{"status": "clean", "message": "No se detectaron patrones de alto riesgo obvios en el snippet."}]
        
    return findings

if __name__ == "__main__":
    mcp.run()