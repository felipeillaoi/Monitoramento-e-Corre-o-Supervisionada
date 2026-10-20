from __future__ import annotations

import argparse
import asyncio
import json
import math
import sqlite3
import time
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
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

UPTIME = "1.3.6.1.2.1.1.3.0"
CPU = "1.3.6.1.2.1.25.3.3.1.2"
IFNAME = "1.3.6.1.2.1.2.2.1.2"
MEM = "1.3.6.1.2.1.25.2.3.1"
RAM_TYPE = "1.3.6.1.2.1.25.2.1.2"
MEM_INDEX = 65536
FIELDS = {
    "nome": (IFNAME, "texto"),
    "mac": ("1.3.6.1.2.1.2.2.1.6", "texto"),
    "admin_status": ("1.3.6.1.2.1.2.2.1.7", "enum"),
    "oper_status": ("1.3.6.1.2.1.2.2.1.8", "enum"),
    "ultima_mudanca": ("1.3.6.1.2.1.2.2.1.9", "ticks"),
    "rx_octetos": ("1.3.6.1.2.1.31.1.1.1.6", "contador64"),
    "tx_octetos": ("1.3.6.1.2.1.31.1.1.1.10", "contador64"),
    "rx_erros": ("1.3.6.1.2.1.2.2.1.14", "contador32"),
    "tx_erros": ("1.3.6.1.2.1.2.2.1.20", "contador32"),
    "rx_descartes": ("1.3.6.1.2.1.2.2.1.13", "contador32"),
    "tx_descartes": ("1.3.6.1.2.1.2.2.1.19", "contador32"),
    "descontinuidade": ("1.3.6.1.2.1.31.1.1.1.19", "ticks"),
}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def integer(value):
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def memory_values(allocation, size, used):
    if any(v is None for v in (allocation, size, used)):
        return None
    if allocation <= 0 or size <= 0 or not 0 <= used <= size:
        return None
    return allocation * size, allocation * used, 100.0 * used / size


def traffic_rates(previous, current, max_gap):
    needed = ("uptime", "rx_octetos", "tx_octetos", "ultima_mudanca", "nome", "mac", "oper_status")
    if any(current.get(k) is None for k in needed):
        return None, None, "dados_indisponiveis"
    if previous is None:
        return None, None, "aguardando_segunda_leitura"
    if any(previous.get(k) is None for k in needed):
        return None, None, "aguardando_segunda_leitura"
    elapsed = current["tempo"] - previous["tempo"]
    if not 0 < elapsed <= max_gap:
        return None, None, "intervalo_invalido"
    if current["nome"] != previous["nome"] or current["mac"] != previous["mac"]:
        return None, None, "interface_alterada"

    if current["uptime"] <= previous["uptime"]:
        return None, None, "uptime_reiniciado"
    device_elapsed = (current["uptime"] - previous["uptime"]) / 100
    if abs(device_elapsed - elapsed) > max(2.0, elapsed * 0.2):
        return None, None, "uptime_descontinuo"
    if current["ultima_mudanca"] != previous["ultima_mudanca"]:
        return None, None, "contadores_descontinuos"
    previous_marker, current_marker = (
        previous.get("descontinuidade"),
        current.get("descontinuidade"),
    )
    if (previous_marker is None) != (current_marker is None):
        return None, None, "disponibilidade_marcador_alterada"
    if current_marker is not None and current_marker != previous_marker:
        return None, None, "contadores_descontinuos"
    if current["oper_status"] != 1 or previous["oper_status"] != 1:
        return None, None, "interface_nao_ativa"
    rx = current["rx_octetos"] - previous["rx_octetos"]
    tx = current["tx_octetos"] - previous["tx_octetos"]
    if rx < 0 or tx < 0:
        return None, None, "contador_reiniciado"
    quality = "estimado_sem_marcador" if current_marker is None else "ok"
    return rx * 8 / elapsed / 1_000_000, tx * 8 / elapsed / 1_000_000, quality


class SnmpFailure(Exception):
    pass


class Client:
    def __init__(self, host, user, auth, privacy, port=161):
        self.host, self.port = host, port
        self.engine = SnmpEngine()
        self.user = UsmUserData(
            user,
            authKey=auth,
            privKey=privacy,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        self.target = None

    async def connect(self):
        self.target = await UdpTransportTarget.create((self.host, self.port), timeout=3, retries=1)

    @staticmethod
    def decode(reply):
        error, status, index, bindings = reply
        if error:
            raise SnmpFailure(str(error))
        if status:
            raise SnmpFailure(f"{status.prettyPrint()} (item {index})")
        return {
            str(oid): None
            if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView))
            else value.prettyPrint()
            for oid, value in bindings
        }

    async def get(self, oids):
        try:
            reply = await asyncio.wait_for(
                get_cmd(
                    self.engine,
                    self.user,
                    self.target,
                    ContextData(),
                    *(ObjectType(ObjectIdentity(oid)) for oid in oids),
                    lookupMib=False,
                ),
                timeout=15,
            )
            return self.decode(reply)
        except (TimeoutError, OSError) as exc:
            raise SnmpFailure(f"{type(exc).__name__}: consulta sem resposta valida") from exc

    async def walk(self, root, limit=64):
        found = {}
        try:
            async with asyncio.timeout(20):
                async for reply in walk_cmd(
                    self.engine,
                    self.user,
                    self.target,
                    ContextData(),
                    ObjectType(ObjectIdentity(root)),
                    lexicographicMode=False,
                    lookupMib=False,
                    maxRows=limit + 1,
                ):
                    for oid, value in self.decode(reply).items():
                        if oid.startswith(root + ".") and value is not None:
                            found[oid] = value
                            if len(found) > limit:
                                raise SnmpFailure("Limite de descoberta excedido")
        except (TimeoutError, OSError) as exc:
            raise SnmpFailure(f"{type(exc).__name__}: descoberta incompleta") from exc
        return found

    def close(self):
        self.engine.close_dispatcher()


def open_database(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS ciclos (
            id INTEGER PRIMARY KEY, instante_utc TEXT NOT NULL, roteador TEXT NOT NULL,
            status TEXT NOT NULL, duracao_ms REAL NOT NULL, diagnostico TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS metricas (
            id INTEGER PRIMARY KEY, ciclo_id INTEGER NOT NULL REFERENCES ciclos(id),
            instante_utc TEXT NOT NULL, escopo TEXT NOT NULL, entidade TEXT NOT NULL,
            metrica TEXT NOT NULL, oid TEXT, bruto TEXT, valor REAL,
            unidade TEXT NOT NULL, status TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_metricas_consulta
            ON metricas(escopo, entidade, metrica, ciclo_id);
    """)
    return db


class Collector:
    def __init__(self, client, db, interval):
        self.client, self.db, self.interval = client, db, interval
        self.cpu_oids, self.interfaces = [], {}
        self.previous = {}
        self.next_discovery = 0.0
        self.discovery_errors = []
        self.last_uptime = None
        self.notified_limitations = set()

    async def discover(self):
        self.discovery_errors = []
        for label, root in (("CPU", CPU), ("interfaces", IFNAME)):
            try:
                values = await self.client.walk(root, 32 if label == "CPU" else 64)
                if label == "CPU":
                    self.cpu_oids = sorted(values, key=lambda x: int(x.rsplit(".", 1)[1]))
                else:
                    self.interfaces = {
                        int(oid.rsplit(".", 1)[1]): name for oid, name in values.items()
                    }
                    self.previous = {k: v for k, v in self.previous.items() if k in self.interfaces}
                if not values:
                    self.discovery_errors.append(f"Tabela {label} nao disponibilizada")
            except SnmpFailure as exc:
                self.discovery_errors.append(f"Descoberta {label}: {exc}")
        self.next_discovery = time.monotonic() + 60
        print(
            f"Descoberta: {len(self.cpu_oids)} indices de CPU; {len(self.interfaces)} interfaces.",
            flush=True,
        )

    async def sample(self):
        started, timestamp = time.monotonic(), utcnow()
        rows, errors = [], list(self.discovery_errors)
        limitations = set()

        def add(scope, entity, metric, value, unit, status="ok", oid=None, raw=None, when=None):
            rows.append(
                (when or utcnow(), scope, str(entity), metric, oid, raw, value, unit, status)
            )

        async def read(scope, entity, specs):
            before = time.monotonic()
            when = utcnow()
            try:
                response = await self.client.get([oid for _, oid, _ in specs])
            except SnmpFailure as exc:
                errors.append(f"{scope}/{entity}: {exc}")
                for metric, oid, unit in specs:
                    add(scope, entity, metric, None, unit, "erro", oid, when=when)
                return None, (before + time.monotonic()) / 2
            data = {}
            for metric, oid, unit in specs:
                raw = response.get(oid)
                value = integer(raw) if unit != "texto" else None
                valid = raw is not None and (unit == "texto" or value is not None)
                optional_missing = (
                    scope == "interface" and metric == "descontinuidade" and raw is None
                )
                if optional_missing:
                    limitations.add(
                        "ifCounterDiscontinuityTime indisponivel: taxas usam verificacao reduzida e recebem estimado_sem_marcador"
                    )
                elif not valid:
                    errors.append(f"OID indisponivel/invalido: {oid}")
                data[metric] = raw if unit == "texto" else value

                numeric = None if unit in ("texto", "contador64") else value
                quality = (
                    "opcional_indisponivel"
                    if optional_missing
                    else "ok"
                    if valid
                    else "indisponivel"
                )
                add(scope, entity, metric, numeric, unit, quality, oid, raw, when)
            return data, (before + time.monotonic()) / 2

        specs = [
            ("uptime", UPTIME, "ticks"),
            ("tipo_memoria", f"{MEM}.2.{MEM_INDEX}", "texto"),
            ("unidade_memoria", f"{MEM}.4.{MEM_INDEX}", "bytes/bloco"),
            ("total_blocos", f"{MEM}.5.{MEM_INDEX}", "blocos"),
            ("usados_blocos", f"{MEM}.6.{MEM_INDEX}", "blocos"),
        ]
        system, _ = await read("sistema", "rb", specs)
        cpu_mean, ram_pct = None, None
        interface_summary = []
        if system is None:
            self.previous.clear()
        else:
            uptime = system["uptime"]
            if uptime is not None and self.last_uptime is not None and uptime < self.last_uptime:
                self.previous.clear()
                self.next_discovery = 0
                errors.append("sysUpTime retrocedeu: reinicializacao do agente/equipamento ou wrap")
            self.last_uptime = uptime
            memory = memory_values(
                system["unidade_memoria"], system["total_blocos"], system["usados_blocos"]
            )
            if system["tipo_memoria"] != RAM_TYPE or memory is None:
                errors.append("RAM sem tipo/unidade/valores validos")
                for metric, unit in (
                    ("memoria_total_bytes", "bytes"),
                    ("memoria_usada_bytes", "bytes"),
                    ("memoria_pct", "%"),
                ):
                    add("sistema", "rb", metric, None, unit, "indisponivel")
            else:
                total, used, ram_pct = memory
                for metric, value, unit in (
                    ("memoria_total_bytes", total, "bytes"),
                    ("memoria_usada_bytes", used, "bytes"),
                    ("memoria_pct", ram_pct, "%"),
                ):
                    add("sistema", "rb", metric, value, unit)

            loads = []
            for offset in range(0, len(self.cpu_oids), 16):
                chunk = self.cpu_oids[offset : offset + 16]
                cpu_data, _ = await read(
                    "cpu", "indices", [(o.rsplit(".", 1)[1], o, "%") for o in chunk]
                )
                if cpu_data:
                    loads.extend(cpu_data.values())
            if (
                self.cpu_oids
                and len(loads) == len(self.cpu_oids)
                and all(v is not None and 0 <= v <= 100 for v in loads)
            ):
                cpu_mean = sum(loads) / len(loads)
            else:
                errors.append("CPU indisponivel ou amostra incompleta")
            add(
                "sistema",
                "rb",
                "cpu_media_indices_pct",
                cpu_mean,
                "%",
                "ok" if cpu_mean is not None else "indisponivel",
            )

            for index, discovered_name in sorted(self.interfaces.items()):
                if_specs = [
                    (name, f"{root}.{index}", unit) for name, (root, unit) in FIELDS.items()
                ]
                if_specs.append(("uptime", UPTIME, "ticks"))
                data, middle = await read("interface", index, if_specs)
                if data is None:
                    self.previous.pop(index, None)
                    continue
                data["tempo"] = middle
                rx, tx, reason = traffic_rates(self.previous.get(index), data, self.interval * 3)
                self.previous[index] = data
                for metric, rate in (("rx_mbps", rx), ("tx_mbps", tx)):
                    add("interface", index, metric, rate, "Mbit/s", reason)
                display_name = data["nome"] or discovered_name
                interface_summary.append(
                    f"{display_name}: RX {fmt(rx)} / TX {fmt(tx)} Mbit/s ({reason})"
                )

        duration = (time.monotonic() - started) * 1000
        status = (
            "falha"
            if system is None
            else "parcial"
            if errors
            else "ok_limitado"
            if limitations
            else "ok"
        )
        with self.db:
            cycle_id = self.db.execute(
                "INSERT INTO ciclos(instante_utc,roteador,status,duracao_ms,diagnostico) VALUES (?,?,?,?,?)",
                (
                    timestamp,
                    self.client.host,
                    status,
                    duration,
                    json.dumps(errors + sorted(limitations), ensure_ascii=False),
                ),
            ).lastrowid
            self.db.executemany(
                "INSERT INTO metricas(ciclo_id,instante_utc,escopo,entidade,metrica,oid,bruto,valor,unidade,status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(cycle_id, *row) for row in rows],
            )
        print(
            f"\n{datetime.now().astimezone():%H:%M:%S} | ciclo {cycle_id} {status} | CPU media {fmt(cpu_mean)}% | RAM {fmt(ram_pct)}%",
            flush=True,
        )
        for line in interface_summary:
            print("  " + line)
        for error in dict.fromkeys(errors):
            print("  AVISO: " + error)
        for limitation in sorted(limitations - self.notified_limitations):
            print("  INFO: " + limitation)
        self.notified_limitations.update(limitations)
        return cycle_id


def fmt(value):
    return "N/D" if value is None else f"{value:.2f}"


async def run(args, auth, privacy):
    db = open_database(args.banco)
    client = Client(args.host, args.usuario, auth, privacy)
    try:
        await client.connect()
        collector = Collector(client, db, args.intervalo)
        count = 0
        print(
            f"Coletor v1.1\nBanco: {args.banco.resolve()}\nAlvo: {args.host}; intervalo: {args.intervalo}s. Ctrl+C encerra.",
            flush=True,
        )
        while args.amostras == 0 or count < args.amostras:
            if time.monotonic() >= collector.next_discovery:
                await collector.discover()
            started = time.monotonic()
            await collector.sample()
            count += 1
            if args.amostras and count >= args.amostras:
                break
            await asyncio.sleep(max(0.1, args.intervalo - (time.monotonic() - started)))
    finally:
        client.close()
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Coletor de laboratorio RB750Gr3 v1.1: SNMPv3 somente leitura e SQLite.\n\nUso: python coletor_snmp.py --amostras 12\n     python coletor_snmp.py                   (Ctrl+C encerra)\nSenhas solicitadas no terminal; nunca armazenadas no banco.\n"
    )
    parser.add_argument("--host", default="192.168.88.1")
    parser.add_argument("--usuario", default="tcc-monitor")
    parser.add_argument("--intervalo", type=float, default=10)
    parser.add_argument("--amostras", type=int, default=0, help="0 = continuo")
    parser.add_argument(
        "--banco", type=Path, default=Path(__file__).resolve().parent / "dados" / "monitoramento.db"
    )
    args = parser.parse_args()
    if not math.isfinite(args.intervalo) or args.intervalo < 5 or args.amostras < 0:
        parser.error("Intervalo deve ser finito e >= 5 segundos; amostras deve ser >= 0")
    auth = getpass("Senha de autenticacao SNMPv3: ")
    privacy = getpass("Senha de criptografia SNMPv3: ")
    if min(len(auth), len(privacy)) < 8:
        parser.error("As duas senhas devem ter pelo menos 8 caracteres")
    asyncio.run(run(args, auth, privacy))


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nColetor encerrado. Os ciclos ja confirmados permanecem no banco.")
    except (OSError, sqlite3.Error, SnmpFailure) as exc:
        raise SystemExit(f"Falha: {exc}")
