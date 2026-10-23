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
    """Extrae de forma segura el JSON de <functioncall> limpiando saltos de línea y comillas."""
    match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if not match:
        return None
    
    # Limpia saltos de línea y tabulaciones que rompen el json.loads en bloques multilínea
    json_str = match.group(0).strip()
    json_str = re.sub(r'[\r\n\t]+', ' ', json_str)
    
    try:
        data = json.loads(json_str)
        if "arguments" in data:
            args = data["arguments"]
            # Si viene como string JSON o string con comillas simples escapadas
            if isinstance(args, str):
                args_clean = args.strip()
                if args_clean.startswith("'") and args_clean.endswith("'"):
                    args_clean = args_clean[1:-1]
                data["arguments"] = json.loads(args_clean)
        return data
    except json.JSONDecodeError:
        try:
            import ast
            evaluated = ast.literal_eval(json_str)
            if "arguments" in evaluated and isinstance(evaluated["arguments"], str):
                evaluated["arguments"] = json.loads(evaluated["arguments"].replace("'", '"'))
            return evaluated
        except Exception as e:
            print(f"[-] Error crítico parseando tool call: {e} | Raw string: {json_str}")
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
    asyncio.run(run_audit("Audit the security headers of http://localhost:8000"))