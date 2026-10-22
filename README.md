
# 🛡️ Vertex-Gemma-MCP: Local AI Security Audit Agent

Agente autónomo de auditoría de seguridad impulsado por **Gemma-2-2B-it** afinado mediante **QLoRA (Unsloth)** para ejecución determinista de herramientas bajo el estándar **Model Context Protocol (MCP)**. Diseñado específicamente para operar en hardware local de bajos recursos (**< 2.2 GB VRAM**).

---

## 🏗️ Arquitectura del Sistema

```
[Usuario / CLI] 
      │
      ▼
[mcp_client_agent.py] ◄─── JSON-RPC (stdio) ───► [mcp_audit_server.py (FastMCP)]
      │                                                   │
      ▼ HTTP (OpenAI API Local)                           ▼ HTTPX (Hardened)
[LM Studio: vertex-gemma-2b-mcp.gguf]            [Target API / Localhost]
```

## 🚀 Características Principales

* **Ultra-Ligero (Low-VRAM Ready):** Cuantización `Q4_K_M` que corre a +40 tokens/seg en GPUs de **4 GB de VRAM**.
* **Fine-Tuning Especializado:** Entrenado sobre `Salesforce/xlam-function-calling-60k` para eliminar alucinaciones en esquemas JSON-RPC.
* **MCP Security Tools:** Auditoría automatizada de cabeceras defensivas (`HSTS`, `CSP`, `X-Frame-Options`, `CORS`) e inspección de superficies OpenAPI/Swagger.
* **SSRF Hardening:** Validación estricta de dominios permitidos (`ALLOWED_HOSTS`) a nivel de protocolo antes de ejecutar peticiones de red.

---

## ⚙️ Instalación y Uso Rápido

### 1. Clonar el repositorio e instalar dependencias
```bash
git clone [https://github.com/tu-usuario/vertex-gemma-mcp.git](https://github.com/tu-usuario/vertex-gemma-mcp.git)
cd vertex-gemma-mcp
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Cargar el modelo `.gguf` en LM Studio
1. Descarga el archivo `vertex-gemma-2b-mcp.gguf` generado con el notebook `training/kaggle_gemma2_2b_qlora.ipynb` (o desde Hugging Face).
2. Cárgalo en **LM Studio -> Local Server** en el puerto `1234` con **Context Length = 2048** y **GPU Offload = Max**.

### 3. Levantar un objetivo de prueba y ejecutar el Agente
En una terminal levanta un servidor local de prueba:
```bash
python -m http.server 8000
```
En otra terminal lanza la auditoría autónoma con Gemma + MCP:
```bash
python src/mcp_client_agent.py
```

---

## 🔒 Estándares de Seguridad (OWASP LLM Top 10)
* **LLM07 (Insecure Plugin Design):** El servidor MCP valida y sanitiza cada URL mediante `urllib.parse` antes de invocar `httpx`.
* **LLM08 (Excessive Agency):** El agente opera únicamente con herramientas de lectura e inspección pasiva, sin permisos de escritura en el sistema anfitrión.

---
**Desarrollado por [Vertex Coders LLC](https://vertexcoders.com)**