
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

# Vertex Gemma MCP — Autonomous Security Audit Agent

Autonomous, lightweight (<4GB VRAM) security audit agent powered by a custom fine-tuned **Gemma-2-2B-it** model (via QLoRA/Unsloth on Kaggle) and integrated natively via the **Model Context Protocol (MCP v2.x)**.

## 🛠️ Architecture Stack
* **LLM Core**: Gemma-2-2B-it (Quantized to Q4_K_M GGUF), fine-tuned with `glaiveai/glaive-function-calling-v2`.
* **Inference Runtime**: LM Studio (Local Server mode with GPU Offload).
* **Protocol**: Model Context Protocol (`MCPServer` over `stdio`).
* **Backend Stack**: Python, `asyncio`, `httpx`, `pydantic`.

---

## 🚀 Available MCP Tools (`mcp_audit_server.py`)

1. **`audit_security_headers(url)`**: Audits defensive HTTP security headers (HSTS, CSP, X-Frame-Options, CORS, Server Banners) on local endpoints.
2. **`inspect_openapi_routes(openapi_json_url)`**: Extracts paths and allowed HTTP methods from a Swagger/OpenAPI schema for attack surface mapping.
3. **`static_code_security_scan(source_code_snippet)`**: Performs static code analysis (SAST) on source snippets to detect dangerous patterns (`eval()`, `exec()`, `shell=True`, SQL injection concatenation, insecure deserialization).

---

## ⚙️ LM Studio Configuration & Prompt Template

To make LM Studio correctly inject the MCP tools into Gemma without throwing system role errors, configure your model's **Jinja Prompt Template** with this exact snippet:

```jinja2
{% for message in messages %}{% if loop.first and message['role'] == 'user' %}{{ '<start_of_turn>user\nYou are a security audit assistant connected to an MCP server.\n' }}{% if tools %}{{ 'You are a helpful assistant with access to the following functions. Use them if required -\n' + (tools | tojson) + '\n\n' }}{% endif %}{{ 'Task: ' + (message['content'] | trim) + '<end_of_turn>\n' }}{% elif message['role'] == 'system' %}{{ '' }}{% else %}{% if (message['role'] == 'assistant') %}{% set role = 'model' %}{% else %}{% set role = 'user' %}{% endif %}{{ '<start_of_turn>' + role + '\n' + (message['content'] | trim) + '<end_of_turn>\n' }}{% endif %}{% endfor %}{% if add_generation_prompt %}{{ '<start_of_turn>model\n' }}{% endif %}