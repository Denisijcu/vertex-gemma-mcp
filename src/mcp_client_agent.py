import asyncio
import json
import re
import sys
from pathlib import Path
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Conexión al Local Server de LM Studio
client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
MODEL_ID = "vertex-gemma-2b-mcp"

def extract_tool_call(response_text: str) -> dict | None:
    """Extrae tool calls de Gemma, manejando fallos de sintaxis por comillas anidadas."""
    match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if not match:
        return None
    
    json_str = match.group(0).strip()
    
    # 1. Intento de decodificación estándar
    try:
        data = json.loads(json_str)
        if "arguments" in data and isinstance(data["arguments"], str):
            data["arguments"] = json.loads(data["arguments"])
        return data
    except Exception:
        pass

    # 2. Extracción de emergencia por Regex para conflictos de comillas en Glaive
    try:
        name_match = re.search(r'"name"\s*:\s*"([^"]+)"', json_str)
        if not name_match:
            return None
        tool_name = name_match.group(1)
        
        # Si es la herramienta de análisis estático, extraemos el snippet directamente por patrón
        if tool_name == "static_code_security_scan":
            code_match = re.search(r'"source_code_snippet"\s*:\s*["\'](.*?)["\']\s*\}', json_str, re.DOTALL)
            if code_match:
                code_snippet = code_match.group(1).replace(r"\'", "'")
                return {
                    "name": tool_name,
                    "arguments": {"source_code_snippet": code_snippet}
                }
                
        # Para otras herramientas con argumentos simples tipo URL
        url_match = re.search(r'"url"\s*:\s*["\'](.*?)["\']', json_str)
        if url_match:
            return {
                "name": tool_name,
                "arguments": {"url": url_match.group(1)}
            }
            
        return None
    except Exception as e:
        print(f"[-] Error crítico en parser de emergencia: {e}")
        return None

async def run_audit(user_task: str):
    server_script = str(Path(__file__).parent / "mcp_audit_server.py")
    
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-u", server_script]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Obtiene las herramientas del MCP Server (Compatible con MCP 2.x y v1)
            tools_res = await session.list_tools()
            tools_list = [
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": getattr(t, "input_schema", getattr(t, "inputSchema", {}))
                }
                for t in tools_res.tools
            ]
            tools_block = json.dumps(tools_list, indent=4)

            # 2. Construye el prompt estricto para Gemma-2-2B
            first_user_msg = (
                "You are a security audit assistant connected to an MCP server.\n"
                "You are a helpful assistant with access to the following functions. "
                f"Use them if required -\n{tools_block}\n\n"
                f"Task: {user_task}"
            )

            print("[*] Consultando a Gemma-2-2B en LM Studio...")
            completion = client.chat.completions.create(
                model=MODEL_ID,
                messages=[{"role": "user", "content": first_user_msg}],
                temperature=0.0,
                max_tokens=150,
                stop=["<end_of_turn>", "<|endoftext|>"]
            )

            model_output = completion.choices[0].message.content.strip()
            print(f"[+] Output de Gemma:\n{model_output}\n")

            # 3. Parsea y ejecuta la herramienta en el MCP Server
            tool_call = extract_tool_call(model_output)
            if tool_call and "name" in tool_call:
                tool_name = tool_call["name"]
                tool_args = tool_call.get("arguments", {})

                print(f"[*] Ejecutando herramienta MCP '{tool_name}' con: {tool_args}...")
                mcp_result = await session.call_tool(tool_name, arguments=tool_args)
                raw_evidence = mcp_result.content[0].text
                print(f"[+] Evidencia del MCP:\n{raw_evidence}\n")

                # 4. Veredicto final respetando la alternancia estricta user -> assistant -> user
                final_report = client.chat.completions.create(
                    model=MODEL_ID,
                    messages=[
                        {"role": "user", "content": first_user_msg},
                        {"role": "assistant", "content": model_output},
                        {
                            "role": "user",
                            "content": (
                                f"FUNCTION RESPONSE: {raw_evidence}\n\n"
                                "Based on this technical output, provide a concise security audit verdict in Spanish."
                            )
                        }
                    ],
                    temperature=0.2,
                    max_tokens=300,
                    stop=["<end_of_turn>", "<|endoftext|>"]
                )
                print(f"=== REPORTE DE AUDITORÍA ===\n{final_report.choices[0].message.content.strip()}")
            else:
                print("[-] No se detectó un JSON de herramienta válido.")

if __name__ == "__main__":
    asyncio.run(run_audit("Perform a static security scan on this snippet: user_input = request.GET.get('cmd'); eval(user_input)"))