import asyncio
import json
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from observacao_wan import WANObserver
from diagnostico_ampliado import wan_signals
from snmp_ether5 import utcnow


async def run():
    print("Teste de observacao WAN v0.5.7 | script fixo de LEITURA | nenhum SET")
    auth = getpass("Senha de autenticacao de tcc-escrita: ")
    privacy = getpass("Senha de criptografia de tcc-escrita: ")
    if min(len(auth), len(privacy)) < 8:
        raise ValueError("Senhas SNMP devem ter pelo menos 8 caracteres.")
    client = WANObserver("tcc-escrita", auth, privacy)
    try:
        await client.connect()
        result = await client.observe()
        record = {
            "versao": "0.5.7",
            "inicio_utc": utcnow(),
            "observacao": result,
            "sinais": wan_signals(result, utcnow()),
        }
        folder = Path(__file__).resolve().parent / "dados" / "testes_observacao_wan"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "_"
            + uuid.uuid4().hex[:8]
            + ".json"
        )
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(record, ensure_ascii=False, indent=2))
        print("Registro:", path)
        return 0 if result.get("tem_dados") and result.get("qualidade") == "ok" else 2
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run()))
    except (KeyboardInterrupt, EOFError):
        raise SystemExit("Interrompido.")
    except (OSError, ValueError) as exc:
        raise SystemExit("Falha: " + str(exc))
