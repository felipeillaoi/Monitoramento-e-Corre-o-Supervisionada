import asyncio
import json
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd, walk_cmd
from snmp_ether5 import Client, DESC, TestFailure, decoded, utcnow

SCRIPT = "tcc-logs-interfaces"
NAMES = "1.3.6.1.4.1.14988.1.1.8.1.1.2"
EXECUTE = "1.3.6.1.4.1.14988.1.1.18.1.1.2"
MARKER = "TCCLOGSv1"


def find_script(rows):
    matches = []
    for oid, value in rows.items():
        if oid.startswith(NAMES + ".") and str(value) == SCRIPT:
            suffix = oid[len(NAMES) + 1 :]
            if suffix.isdigit() and int(suffix) > 0:
                matches.append(suffix)
    if len(matches) != 1:
        raise TestFailure("Nao encontrado exatamente um script tcc-logs-interfaces.")
    return matches[0]


def parse_output(text):
    if (
        not isinstance(text, str)
        or len(text) > 1600
        or not text.splitlines()
        or text.splitlines()[0] != MARKER
    ):
        raise TestFailure("Saida SNMP do script nao corresponde ao formato esperado.")
    lines = text[len(MARKER) :].strip().splitlines()
    if lines == ["SEM_ENTRADAS_NO_FILTRO"]:
        return []
    if not 1 <= len(lines) <= 5 or any(" | " not in line for line in lines):
        raise TestFailure("Extrato de logs malformado.")
    return lines


async def read_logs(client):
    board = decoded(
        await asyncio.wait_for(
            get_cmd(
                client.engine,
                client.user,
                client.target,
                ContextData(),
                ObjectType(ObjectIdentity(DESC)),
                lookupMib=False,
            ),
            timeout=10,
        )
    )
    if "rb750gr3" not in str(board[DESC]).lower():
        raise TestFailure("Equipamento nao corresponde a RB750Gr3.")
    rows = {}

    async with asyncio.timeout(25):
        async for response in walk_cmd(
            client.engine,
            client.user,
            client.target,
            ContextData(),
            ObjectType(ObjectIdentity(NAMES)),
            lexicographicMode=False,
            lookupMib=False,
            maxRows=65,
        ):
            rows.update(decoded(response))
    suffix = find_script(rows)
    oid = EXECUTE + "." + suffix

    values = decoded(
        await asyncio.wait_for(
            get_cmd(
                client.engine,
                client.user,
                client.target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lookupMib=False,
            ),
            timeout=15,
        )
    )
    raw = str(values[oid])
    return {
        "utc_consulta": utcnow(),
        "script": SCRIPT,
        "oid_execucao_GET": oid,
        "saida_original": raw,
        "linhas": parse_output(raw),
        "limites": [
            "Extrato de ate cinco mensagens; nao e o historico completo.",
            "A hora do evento e a informada pelo roteador; UTC da consulta nao e a hora do evento.",
            "Mensagens podem estar antigas ou truncadas. Nao provam causa por si so.",
        ],
    }


async def run():
    folder = Path(__file__).resolve().parent / "dados" / "testes_logs_snmp"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8] + ".json"
    )
    record = {"inicio_utc": utcnow(), "versao": "0.3.1", "metodo": "SNMP_GET_script_leitura"}
    client = None
    try:
        print("Teste de logs por SNMP: script preinstalado tcc-logs-interfaces")
        auth = getpass("Senha de autenticacao de tcc-escrita: ")
        privacy = getpass("Senha de criptografia de tcc-escrita: ")
        if min(len(auth), len(privacy)) < 8:
            raise TestFailure("Senhas precisam ter pelo menos oito caracteres.")
        client = Client("tcc-escrita", auth, privacy)
        await client.connect()
        record["dados"] = await read_logs(client)
        record["resultado"] = "extrato_recebido"
        print("RESULTADO: extrato_recebido")
        for line in record["dados"]["linhas"]:
            print("  " + line)
        if not record["dados"]["linhas"]:
            print("Sem mensagens no filtro; isso nao significa ausencia de problemas.")
    except Exception as exc:
        record["resultado"] = "nao_confirmado"
        record["erro"] = str(exc) if isinstance(exc, TestFailure) else type(exc).__name__
        print("RESULTADO: nao_confirmado |", record["erro"])
    finally:
        if client is not None:
            client.close()
        record["fim_utc"] = utcnow()
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        print("Registro:", path)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except (KeyboardInterrupt, EOFError):
        print("Interrompido.")
