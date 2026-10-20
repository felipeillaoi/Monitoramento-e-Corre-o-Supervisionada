from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone

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
        self.write_target = None

    async def connect(self):
        self.target = await UdpTransportTarget.create((HOST, 161), timeout=3, retries=1)
        self.write_target = await UdpTransportTarget.create((HOST, 161), timeout=3, retries=0)

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
                    self.write_target,
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
