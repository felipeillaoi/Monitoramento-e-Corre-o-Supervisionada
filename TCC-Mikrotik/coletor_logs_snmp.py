from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd, walk_cmd
from logs_snmp import (
    Archive,
    Snapshot,
    FileSnapshot,
    BEGIN_SCRIPT,
    NEXT_SCRIPT,
    DEFAULT_DB,
    BEGIN_SCRIPT_V3,
    NEXT_SCRIPT_V3,
    MAX_FRAMES,
    LogError,
    utcnow,
)
from snmp_ether5 import Client, DESC, UPTIME, HOST, decoded
from teste_logs_snmp import NAMES, EXECUTE


def discover_scripts(rows, protocol=2):
    found = {}
    names = (BEGIN_SCRIPT_V3, NEXT_SCRIPT_V3) if protocol == 3 else (BEGIN_SCRIPT, NEXT_SCRIPT)
    for name in names:
        matches = [
            oid[len(NAMES) + 1 :]
            for oid, value in rows.items()
            if oid.startswith(NAMES + ".") and str(value) == name
        ]
        if len(matches) != 1 or not matches[0].isdigit() or int(matches[0]) <= 0:
            raise LogError("Exigido exatamente um script instalado com nome " + name)
        found[name] = EXECUTE + "." + matches[0]
    return found


async def identify(client):
    data = decoded(
        await get_cmd(
            client.engine,
            client.user,
            client.target,
            ContextData(),
            ObjectType(ObjectIdentity(DESC)),
            ObjectType(ObjectIdentity(UPTIME)),
            lookupMib=False,
        )
    )
    if "rb750gr3" not in str(data[DESC]).lower():
        raise LogError("Alvo nao corresponde a RB750Gr3.")
    return int(data[UPTIME])


async def discover(client, protocol=2):
    rows = {}
    async with asyncio.timeout(25):
        async for reply in walk_cmd(
            client.engine,
            client.user,
            client.target,
            ContextData(),
            ObjectType(ObjectIdentity(NAMES)),
            lexicographicMode=False,
            lookupMib=False,
            maxRows=256,
        ):
            rows.update(decoded(reply))
    return discover_scripts(rows, protocol)


async def execute_get(client, oid):
    values = decoded(
        await asyncio.wait_for(
            get_cmd(
                client.engine,
                client.user,
                client.write_target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lookupMib=False,
            ),
            timeout=15,
        )
    )
    value = values[oid]
    return value.asOctets().decode("ascii") if hasattr(value, "asOctets") else str(value)


async def collect(client, archive, folder, protocol=2):
    record = {
        "id": uuid.uuid4().hex,
        "versao": "logs-0.2",
        "protocolo": protocol,
        "inicio_utc": utcnow(),
        "host": HOST,
        "metodo": "SNMP_GET_scripts_snapshot_RAM",
        "resultado": "nao_confirmado",
    }
    snapshot, uptime, interrupted = None, None, False
    path = folder / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + record["id"][:8] + ".json"
    )
    start = time.monotonic()
    try:
        async with asyncio.timeout(300):
            uptime = await identify(client)
            scripts = await discover(client) if protocol == 2 else await discover(client, protocol)
            record["scripts_e_OIDs"] = scripts
            begin_name, next_name = (
                (BEGIN_SCRIPT_V3, NEXT_SCRIPT_V3) if protocol == 3 else (BEGIN_SCRIPT, NEXT_SCRIPT)
            )
            manifest = await execute_get(client, scripts[begin_name])
            record["manifesto"] = manifest
            snapshot = FileSnapshot(manifest) if protocol == 3 else Snapshot(manifest)
            for _ in range(MAX_FRAMES + 1):
                raw = await execute_get(client, scripts[next_name])
                record["ultimo_bloco_recebido"] = raw
                snapshot.feed(raw)
                if snapshot.finished:
                    end_uptime = await identify(client)
                    if end_uptime < uptime:
                        raise LogError("Uptime regrediu durante a coleta; nao confirmar snapshot.")
                    record["resultado"] = "snapshot_completo"
                    break
                if snapshot.sequence % 100 == 0:
                    progress = (
                        f"{len(snapshot.buffer)}/{snapshot.size} bytes"
                        if protocol == 3
                        else f"{len(snapshot.rows)}/{snapshot.count} mensagens"
                    )
                    print(f"  Progresso: {progress}; {snapshot.sequence} blocos.", flush=True)
            else:
                raise LogError("Limite de blocos atingido sem END.")
    except asyncio.CancelledError:
        record["erro"] = "Coleta interrompida; snapshot incompleto."
        interrupted = True
    except Exception as exc:
        record["erro"] = (
            str(exc)
            if isinstance(exc, (LogError, TimeoutError)) or type(exc).__name__ == "TestFailure"
            else type(exc).__name__
        )
    finally:
        record["fim_utc"] = utcnow()
        record["duracao_s"] = round(time.monotonic() - start, 3)
        rows = snapshot.rows if snapshot else []
        record["quantidade_anunciada"] = snapshot.count if snapshot else None
        record["blocos_recebidos"] = snapshot.sequence if snapshot else 0
        if record["resultado"] != "snapshot_completo" and rows:
            record["resultado"] = "parcial"
        archive.save(HOST, uptime, record, rows)
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        print(
            "RESULTADO:",
            record["resultado"],
            "| recebidas:",
            len(rows),
            "| novas:",
            record.get("mensagens_novas_arquivadas", 0),
            "| segundos:",
            record["duracao_s"],
            flush=True,
        )
        if "erro" in record:
            print("  Erro:", record["erro"], flush=True)
        if record.get("sem_sobreposicao_com_ultimo_evento") or record.get("uptime_regrediu"):
            print(
                "  Cobertura reduzida: conferir indicacoes no registro; nao e uma contagem de perdas.",
                flush=True,
            )
        print("Registro:", path, flush=True)
    if interrupted:
        raise asyncio.CancelledError
    return record


async def run(args):
    folder = Path(__file__).resolve().parent / "dados" / "coletas_logs_snmp"
    folder.mkdir(parents=True, exist_ok=True)
    args.banco.parent.mkdir(parents=True, exist_ok=True)
    lock = args.banco.with_suffix(".lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise LogError(
            "Coletor ja ativo ou trava remanescente: "
            + str(lock)
            + ". Encerre a outra instancia; se ela ja terminou, remova somente essa trava .lock."
        ) from exc
    client, archive = None, None
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(str(os.getpid()))
        print(
            f"Coletor de logs SNMP v0.2 | protocolo v{args.protocolo} | todas as categorias em /log | sem SET",
            flush=True,
        )
        auth = getpass("Senha de autenticacao de tcc-escrita: ")
        privacy = getpass("Senha de criptografia de tcc-escrita: ")
        if min(len(auth), len(privacy)) < 8:
            raise LogError("Senhas precisam ter pelo menos oito caracteres.")
        client = Client("tcc-escrita", auth, privacy)
        await client.connect()
        archive = Archive(args.banco)
        cycle = 0
        while args.ciclos == 0 or cycle < args.ciclos:
            cycle += 1
            print(f"\nColeta {cycle} | banco: {args.banco}", flush=True)
            result = await collect(client, archive, folder, args.protocolo)

            if args.ciclos != 0 and cycle >= args.ciclos:
                return 0 if result["resultado"] == "snapshot_completo" else 1
            await asyncio.sleep(args.intervalo)
    finally:
        if archive is not None:
            archive.close()
        if client is not None:
            client.close()
        lock.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description="Coleta paginada de todas as mensagens disponiveis em /log, via SNMPv3."
    )
    parser.add_argument(
        "--ciclos", type=int, default=1, help="1: ensaio unico; 0: continuo ate Ctrl+C."
    )
    parser.add_argument(
        "--intervalo", type=float, default=60, help="Espera apos cada coleta, em segundos."
    )
    parser.add_argument("--banco", type=Path, default=DEFAULT_DB)
    parser.add_argument(
        "--protocolo",
        type=int,
        choices=(2, 3),
        default=3,
        help="3: tmpfs e variaveis locais (padrao); 2: experimento com globais, bloqueado no ensaio SNMP.",
    )
    args = parser.parse_args()
    if args.ciclos < 0 or not 10 <= args.intervalo <= 86400:
        parser.error("Use ciclos >= 0 e intervalo entre 10 e 86400 segundos.")
    try:
        return asyncio.run(run(args))
    except (KeyboardInterrupt, EOFError):
        print("Interrompido.")
        return 1
    except LogError as exc:
        print("Falha:", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
