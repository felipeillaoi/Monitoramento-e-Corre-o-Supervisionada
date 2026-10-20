from __future__ import annotations

import argparse
import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    walk_cmd,
    set_cmd,
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto.rfc1902 import Integer
from pysnmp.proto.rfc1905 import NoSuchInstance, NoSuchObject, EndOfMibView

HOST = "192.168.88.1"
NAME = "ether5"
MAC = "D0:EA:11:0B:47:EA"
DESC = "1.3.6.1.2.1.1.1.0"
UPTIME = "1.3.6.1.2.1.1.3.0"
IFDESCR = "1.3.6.1.2.1.2.2.1.2"
IFTYPE = "1.3.6.1.2.1.2.2.1.3"
IFMAC = "1.3.6.1.2.1.2.2.1.6"
ADMIN = "1.3.6.1.2.1.2.2.1.7"
OPER = "1.3.6.1.2.1.2.2.1.8"


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class TestFailure(Exception):
    pass


class Journal:
    def __init__(self, folder, enable):
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "_"
            + uuid.uuid4().hex[:8]
            + ".json"
        )
        self.data = {
            "versao": "0.1",
            "inicio_utc": utcnow(),
            "host": HOST,
            "interface": NAME,
            "mac_esperado": MAC,
            "habilitar_solicitado": enable,
            "eventos": [],
        }
        self.add("inicio")

    def add(self, event, **details):
        self.data["eventos"].append({"utc": utcnow(), "evento": event, **details})
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as stream:
            json.dump(self.data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, self.path)


def decoded(reply):
    error, status, index, bindings = reply
    if error:
        raise TestFailure("SNMP: " + str(error))
    if status:
        raise TestFailure(f"SNMP: {status.prettyPrint()} (item {index})")
    result = {}
    for oid, value in bindings:
        if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
            raise TestFailure(f"OID indisponivel: {oid}")
        result[str(oid)] = value
    return result


class Client:
    def __init__(self, username, auth, privacy):
        self.engine = SnmpEngine()
        self.user = UsmUserData(
            username,
            authKey=auth,
            privKey=privacy,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        self.target = None

    async def connect(self):
        self.target = await UdpTransportTarget.create((HOST, 161), timeout=3, retries=0)

    async def discover(self):
        matches = []
        async with asyncio.timeout(20):
            async for reply in walk_cmd(
                self.engine,
                self.user,
                self.target,
                ContextData(),
                ObjectType(ObjectIdentity(IFDESCR)),
                lexicographicMode=False,
                lookupMib=False,
                maxRows=65,
            ):
                for oid, value in decoded(reply).items():
                    if oid.startswith(IFDESCR + ".") and str(value) == NAME:
                        matches.append(int(oid.rsplit(".", 1)[1]))
        if len(matches) != 1:
            raise TestFailure("A descoberta nao encontrou exatamente uma ether5.")
        return matches[0]

    async def snapshot(self, idx):
        oids = [DESC, UPTIME] + [f"{root}.{idx}" for root in (IFDESCR, IFTYPE, IFMAC, ADMIN, OPER)]
        values = decoded(
            await asyncio.wait_for(
                get_cmd(
                    self.engine,
                    self.user,
                    self.target,
                    ContextData(),
                    *(ObjectType(ObjectIdentity(oid)) for oid in oids),
                    lookupMib=False,
                ),
                timeout=10,
            )
        )
        return {
            "utc": utcnow(),
            "ifindex": idx,
            "descricao": str(values[DESC]),
            "uptime_ticks": int(values[UPTIME]),
            "nome": str(values[f"{IFDESCR}.{idx}"]),
            "tipo": int(values[f"{IFTYPE}.{idx}"]),
            "mac": ":".join(f"{x:02X}" for x in values[f"{IFMAC}.{idx}"].asOctets()),
            "admin_status": int(values[f"{ADMIN}.{idx}"]),
            "oper_status": int(values[f"{OPER}.{idx}"]),
        }

    async def enable(self, idx):
        try:
            reply = await asyncio.wait_for(
                set_cmd(
                    self.engine,
                    self.user,
                    self.target,
                    ContextData(),
                    ObjectType(ObjectIdentity(f"{ADMIN}.{idx}"), Integer(1)),
                    lookupMib=False,
                ),
                timeout=10,
            )
            error, status, index, bindings = reply
            if error:
                return {"resultado": "indeterminado", "detalhe": str(error)}
            if status:
                return {
                    "resultado": "recusado",
                    "detalhe": status.prettyPrint(),
                    "item": int(index),
                }
            pairs = decoded(reply)
            if int(pairs.get(f"{ADMIN}.{idx}", -1)) != 1:
                return {"resultado": "indeterminado", "detalhe": "Resposta SET inesperada"}
            return {"resultado": "aceito", "detalhe": "noError"}
        except Exception as exc:
            return {"resultado": "indeterminado", "detalhe": type(exc).__name__}

    def close(self):
        self.engine.close_dispatcher()


def validate(state, previous=None):
    if (
        state["nome"] != NAME
        or state["mac"] != MAC
        or state["tipo"] != 6
        or "rb750gr3" not in state["descricao"].lower()
    ):
        raise TestFailure("Identidade inesperada: exigidos RB750Gr3, ether5, Ethernet e MAC " + MAC)
    if state["admin_status"] not in (1, 2, 3) or state["oper_status"] not in range(1, 8):
        raise TestFailure("Estado de interface fora da faixa valida.")
    if state["uptime_ticks"] < 0:
        raise TestFailure("Uptime invalido.")
    if previous is not None:
        if (
            state["ifindex"] != previous["ifindex"]
            or state["uptime_ticks"] < previous["uptime_ticks"]
        ):
            raise TestFailure("Indice alterado ou uptime regrediu durante o teste.")


def show(state):
    print(f"  {state['nome']} | ifindex={state['ifindex']} | MAC={state['mac']}")
    print(f"  admin_status={state['admin_status']} | oper_status={state['oper_status']}")


async def exercise(client, journal, enable=False, pause=1):
    idx = await client.discover()
    before = await client.snapshot(idx)
    journal.add("leitura_inicial", dados=before)
    validate(before)
    show(before)
    if not enable:
        return "somente_leitura"
    if before["admin_status"] == 1:
        return "ja_habilitada_sem_SET"
    if before["admin_status"] != 2 or before["oper_status"] == 1:
        raise TestFailure("Teste exige ether5 administrativamente down e sem link ativo.")
    fresh = await client.snapshot(idx)
    journal.add("pre_condicao", dados=fresh)
    validate(fresh, before)
    if fresh["admin_status"] != 2 or fresh["oper_status"] == 1:
        raise TestFailure("Estado mudou antes do SET; tentativa cancelada.")

    journal.add("SET_a_enviar", oid=f"{ADMIN}.{idx}", tipo="INTEGER", valor=1)
    result = await client.enable(idx)
    journal.add("resposta_SET", **result)
    print("  SET:", result["resultado"], "|", result["detalhe"])
    last = None
    for _ in range(3):
        await asyncio.sleep(pause)
        try:
            after = await client.snapshot(idx)
            journal.add("verificacao_GET", dados=after)
            validate(after, fresh)
            last = after
        except (TestFailure, TimeoutError, OSError) as exc:
            journal.add("verificacao_falhou", erro=type(exc).__name__)
            continue
        show(after)
        if after["admin_status"] == 1:
            return (
                "habilitacao_confirmada"
                if result["resultado"] == "aceito"
                else "habilitada_sem_confirmacao_do_SET"
            )
    if result["resultado"] == "recusado":
        return "SET_recusado"
    return "habilitacao_nao_confirmada" if last else "resultado_indeterminado"


MESSAGES = {
    "somente_leitura": "Leitura concluida. Nenhum SET enviado.",
    "ja_habilitada_sem_SET": "A ether5 ja estava habilitada. Nenhum SET enviado; escrita ainda nao testada.",
    "habilitacao_confirmada": "SET aceito e admin_status=1 confirmado por GET. Habilitacao administrativa comprovada.",
    "habilitada_sem_confirmacao_do_SET": "GET indica habilitada, mas o SET nao foi confirmado. Nao atribuir a mudanca ao teste sem investigar.",
    "SET_recusado": "Roteador recusou o SET. Registrar o erro; verificar suporte do OID e permissoes.",
    "habilitacao_nao_confirmada": "Nao foi confirmada a habilitacao por GET. Nao declarar sucesso.",
    "resultado_indeterminado": "Sem leitura final valida. Conferir o estado no MikroTik; nao repetir SET automaticamente.",
}


async def run(args):
    journal = Journal(Path(__file__).resolve().parent / "dados" / "testes_atuacao", args.habilitar)
    client = None
    try:
        print("Teste de atuacao SNMPv3 v0.1 | RB750Gr3 | ether5")
        print("Modo:", "habilitar via SET" if args.habilitar else "somente leitura")
        print("Registro:", journal.path)
        auth = getpass("Senha de autenticacao de tcc-escrita: ")
        privacy = getpass("Senha de criptografia de tcc-escrita: ")
        if min(len(auth), len(privacy)) < 8:
            raise TestFailure("As duas senhas precisam ter pelo menos 8 caracteres.")
        client = Client("tcc-escrita", auth, privacy)
        del auth, privacy
        await client.connect()
        result = await exercise(client, journal, args.habilitar)
        journal.add("fim", resultado=result)
        print("\nRESULTADO:", result)
        print(MESSAGES[result])
        print("Sem cabo, oper_status pode permanecer 2 mesmo com admin_status=1.")
        return (
            0
            if result in ("somente_leitura", "ja_habilitada_sem_SET", "habilitacao_confirmada")
            else 2
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        journal.add(
            "interrompido",
            observacao="Se SET_a_enviar foi registrado, verificar o estado no roteador.",
        )
        print("Interrompido. Confira a ether5 no MikroTik se o envio ja havia iniciado.")
        return 130
    except Exception as exc:
        detail = str(exc) if isinstance(exc, TestFailure) else type(exc).__name__
        journal.add("erro", detalhe=detail)
        print("TESTE INTERROMPIDO:", detail)
        return 2
    finally:
        if client is not None:
            client.close()
        print("Registro:", journal.path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Teste de bancada v0.1: leitura e habilitacao da ether5 por SNMPv3.\n\nSem --habilitar: somente leitura. Nao usa Ollama, SSH ou banco do coletor.\nAlvo e MAC fixados para a RB750Gr3 do laboratorio do TCC.\n"
    )
    parser.add_argument(
        "--habilitar", action="store_true", help="Tentar INTEGER 1 no ifAdminStatus da ether5"
    )
    raise SystemExit(asyncio.run(run(parser.parse_args())))
