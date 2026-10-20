from __future__ import annotations
import asyncio
import ipaddress
import json
import re
from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd, walk_cmd
from snmp_ether5 import Client, DESC, UPTIME, decoded, utcnow, TestFailure
from investigacao_interfaces import PORTS

SCRIPT = "tcc-observar-wan-v1"
NAMES = "1.3.6.1.4.1.14988.1.1.8.1.1.2"
EXECUTE = "1.3.6.1.4.1.14988.1.1.18.1.1.2"
MARKER = "TCCWANv1|"
TOOL = {
    "type": "function",
    "function": {
        "name": "consultar_estado_wan",
        "description": "Observa cliente DHCP de ether1, IPv4, rota padrao main, DNS configurado e disco via script preinstalado de leitura; nao corrige.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
}


def locate(rows):
    suffixes = [
        oid[len(NAMES) + 1 :]
        for oid, value in rows.items()
        if oid.startswith(NAMES + ".") and str(value) == SCRIPT
    ]
    if len(suffixes) != 1 or not suffixes[0].isdigit() or int(suffixes[0]) <= 0:
        raise TestFailure("Instale exatamente um script " + SCRIPT + ".")
    return EXECUTE + "." + suffixes[0]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Campo repetido na observacao WAN.")
        result[key] = value
    return result


def dhcp_flag(value, field):
    if type(value) is bool:
        return value
    if value is None:
        return None
    if isinstance(value, str):
        if value in ("yes", "true"):
            return True
        if value in ("no", "false"):
            return False
        if value == "":
            return None
    raise ValueError(
        "Flag DHCP " + field + " com tipo/valor nao suportado (" + type(value).__name__ + ")."
    )


def response_diagnostics(raw):
    if not isinstance(raw, str):
        return {"tipo_texto": False}
    position = raw.find(MARKER)
    result = {
        "tipo_texto": True,
        "bytes_utf8": len(raw.encode("utf-8")),
        "posicao_marcador": position,
        "quantidade_marcadores": raw.count(MARKER),
        "termina_com_chave": raw.rstrip().endswith("}"),
        "somente_numeros": bool(re.fullmatch(r"\s*[0-9]+(?:\s+[0-9]+)*\s*", raw)),
    }
    if raw.startswith(MARKER) and result["bytes_utf8"] <= 1800:
        try:
            data = json.loads(raw[len(MARKER) :], object_pairs_hook=unique_object)
            client = data.get("dhcp") if isinstance(data, dict) else None
            if isinstance(client, dict):
                result["tipos_flags_dhcp"] = {
                    key: type(client[key]).__name__ if key in client else "ausente"
                    for key in ("disabled", "invalid")
                }
        except (ValueError, TypeError):
            pass
    return result


def parse_snapshot(raw):
    if not isinstance(raw, str):
        raise ValueError("Resposta WAN nao textual.")
    if len(raw.encode("utf-8")) > 1800:
        raise ValueError("Resposta WAN excedeu o limite de 1800 bytes.")
    if not raw.startswith(MARKER):
        if any(
            word in raw.lower()
            for word in ("not enough permissions", "permission denied", "not permitted")
        ):
            raise ValueError(
                "Script WAN retornou erro de permissao; conferir policy e acesso SNMP."
            )
        if MARKER in raw:
            raise ValueError("Saida extra antes de TCCWANv1; atualize o script WAN para v0.5.2.")
        if response_diagnostics(raw)["somente_numeros"]:
            raise ValueError(
                "Resposta WAN contem apenas contagem; atualize o script WAN para v0.5.2."
            )
        raise ValueError("Marcador TCCWANv1 ausente na resposta WAN.")
    try:
        d = json.loads(raw[len(MARKER) :], object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "JSON WAN invalido ou incompleto; conferir diagnostico_resposta, sem recuperar dados parciais."
        ) from exc
    required = {
        "version",
        "interface",
        "mac",
        "dhcp_count",
        "dhcp",
        "ipv4_count",
        "default_routes",
        "dns_servers",
        "doh_configured",
        "free_hdd",
        "total_hdd",
        "errors",
    }
    if (
        not isinstance(d, dict)
        or set(d) != required
        or type(d["version"]) is not int
        or d["version"] != 1
    ):
        raise ValueError("Protocolo WAN desconhecido.")
    if (
        d["interface"] != "ether1"
        or not isinstance(d["mac"], str)
        or d["mac"].upper() != PORTS["ether1"]["mac"]
    ):
        raise ValueError("Identidade WAN nao corresponde ao laboratorio.")
    for key in ("dhcp_count", "ipv4_count", "default_routes", "dns_servers"):
        if type(d[key]) is not int or not -1 <= d[key] <= 65535:
            raise ValueError("Contagem WAN invalida: " + key)
    for key in ("free_hdd", "total_hdd"):
        if type(d[key]) is not int or not -1 <= d[key] <= 2**53:
            raise ValueError("Espaco de disco invalido.")
    if d["free_hdd"] >= 0 and d["total_hdd"] >= 0 and d["free_hdd"] > d["total_hdd"]:
        raise ValueError("Espaco livre maior que total.")
    if not isinstance(d["errors"], str) or not re.fullmatch(
        r"(?:;(?:dhcp|ipv4|route|dns|disk))*", d["errors"]
    ):
        raise ValueError("Marcadores de qualidade invalidos.")
    if type(d["doh_configured"]) is not bool:
        raise ValueError("Flag DoH deve ser booleana.")
    unknown = []
    converted = {}
    if d["dhcp_count"] == 1:
        c = d["dhcp"]
        if not isinstance(c, dict) or set(c) != {
            "id",
            "disabled",
            "invalid",
            "status",
            "address",
            "gateway",
            "add_default_route",
        }:
            raise ValueError("Cliente DHCP incompleto.")
        if not isinstance(c["id"], str) or not re.fullmatch(r"\*[0-9A-Fa-f]+", c["id"]):
            raise ValueError("Identificador DHCP invalido.")
        for key in ("disabled", "invalid"):
            original = c[key]
            c[key] = dhcp_flag(original, key)
            if type(original) is not bool:
                converted[key] = (
                    type(original).__name__ + "->" + ("desconhecido" if c[key] is None else "bool")
                )
            if c[key] is None:
                unknown.append("dhcp." + key)
        if not isinstance(c["status"], str) or c["status"] not in (
            "",
            "stopped",
            "searching",
            "requesting",
            "bound",
            "renewing",
            "rebinding",
            "error",
            "stopping",
        ):
            raise ValueError("Estado DHCP desconhecido; nao interpretar como saudavel.")
        if c["add_default_route"] not in ("yes", "no", "special-classless", "true", "false"):
            raise ValueError("Configuracao de rota DHCP desconhecida.")
        for key in ("address", "gateway"):
            if not isinstance(c[key], str) or len(c[key]) > 64:
                raise ValueError("Endereco DHCP invalido.")
            if c[key]:
                value = (
                    ipaddress.ip_interface(c[key])
                    if key == "address"
                    else ipaddress.ip_address(c[key])
                )
                if value.version != 4:
                    raise ValueError("Perfil DHCP exige IPv4.")
        if c["status"] == "bound" and (
            c["disabled"] is True or not c["address"] or c["address"].startswith("0.0.0.0/")
        ):
            raise ValueError("Estado DHCP contraditorio.")
    elif d["dhcp"] != "":
        raise ValueError("Cliente DHCP ambiguo nao pode ter detalhe escolhido arbitrariamente.")
    result = {
        "tem_dados": True,
        "utc": utcnow(),
        "origem": "SNMP_GET_script_leitura",
        "qualidade": "parcial" if d["errors"] or unknown else "ok",
        **d,
    }
    if unknown:
        result["campos_indisponiveis"] = unknown
    if converted:
        result["normalizacao_flags_dhcp"] = converted
    return result


class WANObserver(Client):
    async def observe(self):
        raw = None
        try:
            values = decoded(
                await asyncio.wait_for(
                    get_cmd(
                        self.engine,
                        self.user,
                        self.target,
                        ContextData(),
                        ObjectType(ObjectIdentity(DESC)),
                        ObjectType(ObjectIdentity(UPTIME)),
                        lookupMib=False,
                    ),
                    timeout=10,
                )
            )
            if "rb750gr3" not in str(values[DESC]).lower():
                raise TestFailure("Alvo nao corresponde a RB750Gr3.")
            before = int(values[UPTIME])
            rows = {}
            async with asyncio.timeout(25):
                async for reply in walk_cmd(
                    self.engine,
                    self.user,
                    self.target,
                    ContextData(),
                    ObjectType(ObjectIdentity(NAMES)),
                    lexicographicMode=False,
                    lookupMib=False,
                    maxRows=256,
                ):
                    rows.update(decoded(reply))
            oid = locate(rows)

            values = decoded(
                await asyncio.wait_for(
                    get_cmd(
                        self.engine,
                        self.user,
                        self.write_target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lookupMib=False,
                    ),
                    timeout=15,
                )
            )
            v = values[oid]
            raw = v.asOctets().decode("utf-8") if hasattr(v, "asOctets") else str(v)
            result = parse_snapshot(raw)
            after = decoded(
                await asyncio.wait_for(
                    get_cmd(
                        self.engine,
                        self.user,
                        self.target,
                        ContextData(),
                        ObjectType(ObjectIdentity(UPTIME)),
                        lookupMib=False,
                    ),
                    timeout=10,
                )
            )
            if int(after[UPTIME]) < before:
                raise TestFailure("Uptime regrediu durante observacao WAN.")
            result["oid_script"] = oid
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure = {
                "tem_dados": False,
                "utc": utcnow(),
                "origem": "SNMP_GET_script_leitura",
                "erro": str(exc)[:200]
                if isinstance(exc, (TestFailure, ValueError))
                else type(exc).__name__,
            }
            if raw is not None:
                failure["diagnostico_resposta"] = response_diagnostics(raw)
            return failure
