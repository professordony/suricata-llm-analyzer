import json
import time
import asyncio
import aiohttp

EVE_LOG = "/var/log/suricata/eve.json"
API_ENDPOINT = "http://localhost:8000/api/analyze_log"
DELAY = 10  # segundos de atraso entre cada envio

async def send_event(session, event):
    try:
        async with session.post(API_ENDPOINT, json=event) as resp:
            print(f"Enviado: {event.get('alert', {}).get('signature')} status={resp.status}")
    except Exception as e:
        print(f"Erro ao enviar evento: {e}")

async def process_logs():
    print("📡 Iniciando ingestão 1-por-1 com atraso")
    async with aiohttp.ClientSession() as session:
        with open(EVE_LOG, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        print(f"📥 Capturado: {event['alert']['signature']}")
                        await send_event(session, event)
                        await asyncio.sleep(DELAY)
                except Exception as e:
                    print(f"❌ Erro processando linha: {e}")

def main():
    asyncio.run(process_logs())

if __name__ == "__main__":
    main()
