import asyncio
import json
import re
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Conexión al Local Server de LM Studio
client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
MODEL_ID = "local-model"  # LM Studio usa el modelo que tengas cargado en memoria

def extract_tool_call(response_text: str) -> dict | None:
    """Extrae el JSON de <functioncall> y convierte 'arguments' de string a dict."""
    match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
        if "arguments" in data and isinstance(data["arguments"], str):
            data["arguments"] = json.loads(data["arguments"])
        return data
    except json.JSONDecodeError:
        return None

async def run_audit(user_task: str):
    server_params = StdioServerParameters(
        command="python",
        args=["src/mcp_audit_server.py"]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Obtiene las herramientas del MCP Server y las formatea al estilo Glaive
            tools_res = await session.list_tools()
            tools_list = [
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.inputSchema
                }
                for t in tools_res.tools
            ]
            tools_Block = json.dumps(tools_list, indent=4)

            # 2. Todo va en 'user' (Gemma prohíbe 'system') y con el formato exacto de Kaggle
            first_user_msg = (
                "You are a security audit assistant connected to an MCP server.\n"
                "You are a helpful assistant with access to the following functions. "
                f"Use them if required -\n{tools_Block}\n\n"
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

                # 4. Respeta la alternancia estricta de Gemma: user -> assistant -> user
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