import hashlib
import json
import math
import re
from datetime import datetime


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def stamp(value):
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else None
    except (ValueError, TypeError):
        return None


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100


def temporal_summary(rows, reference):
    end = stamp(reference)
    if end is None:
        raise ValueError("Referencia temporal sem fuso.")
    accepted, invalid_time = [], 0
    for row in rows:
        when = stamp(row.get("utc"))
        age = (end - when).total_seconds() if when else None
        if age is None or age < 0:
            invalid_time += 1
        elif age <= 1200:
            accepted.append((when, age, row))
    accepted.sort(key=lambda item: item[0])
    gaps = [(b[0] - a[0]).total_seconds() for a, b in zip(accepted, accepted[1:])]
    result = {
        "referencia_utc": reference,
        "janela_max_s": 1200,
        "amostras_recebidas": len(rows),
        "amostras_na_janela": len(accepted),
        "tempos_invalidos": invalid_time,
        "maior_lacuna_s": round(max(gaps), 3) if gaps else None,
        "inicio_utc": accepted[0][2]["utc"] if accepted else None,
        "fim_utc": accepted[-1][2]["utc"] if accepted else None,
        "idade_ultima_amostra_s": round(accepted[-1][1], 3) if accepted else None,
        "nota": "Janelas temporais, nao periodos comprovadamente saudaveis ou anteriores a uma falha. Lacunas/valores invalidos sao informados; resumo nao substitui leitura atual.",
    }
    for metric in ("cpu_pct", "ram_pct"):
        stats = {}
        for label, lower, upper in (("recente_0a300s", -1, 300), ("anterior_300a1200s", 300, 1200)):
            subset = [r for _, age, r in accepted if lower < age <= upper]
            values = [r[metric] for r in subset if number(r.get(metric))]
            stats[label] = {
                "n": len(values),
                "ausentes_ou_invalidas": len(subset) - len(values),
                "min": round(min(values), 3) if values else None,
                "media": round(sum(values) / len(values), 3) if values else None,
                "max": round(max(values), 3) if values else None,
            }
        a, b = stats["anterior_300a1200s"], stats["recente_0a300s"]
        enough = (
            min(a["n"], b["n"]) >= 3
            and invalid_time == 0
            and not a["ausentes_ou_invalidas"]
            and not b["ausentes_ou_invalidas"]
            and bool(accepted)
            and accepted[-1][1] <= 120
            and max(gaps, default=0) <= 30
        )
        stats["comparacao_com_cobertura_minima"] = enough
        stats["variacao_media_pp"] = round(b["media"] - a["media"], 3) if enough else None
        result[metric] = stats
    return result


def sanitize(value, secrets=()):
    if isinstance(value, dict):
        return {
            str(k): sanitize(v, secrets)
            for k, v in value.items()
            if str(k).lower()
            not in ("mac", "host", "usuario", "password", "api_key", "authorization")
        }
    if isinstance(value, list):
        return [sanitize(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[SEGREDO_REMOVIDO]")
    if re.search(r"(?i)new script added|script changed|/system script.*source", value):
        return "[Conteudo de configuracao de script omitido]"
    value = re.sub(
        r'(?i)\b(?:password|passwd|senha|authentication-password|encryption-password|private-key|api[_-]?key)\s*[=:]\s*(?:"[^"]*"|\S+)',
        "[CREDENCIAL_REMOVIDA]",
        value,
    )
    value = re.sub(r"\bsk-[A-Za-z0-9_-]+", "[CHAVE_REMOVIDA]", value)
    value = re.sub(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", "[IP]", value)
    value = re.sub(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", "[MAC]", value)
    value = re.sub(r"[\w.+-]+@(?=\[IP\])", "[USUARIO]@", value)
    return value


def make_packet(agent, candidates, states, details, reference):
    from analise_logs import catalogue

    evidence = agent.record.get("ferramentas", [])
    facts = []

    selected = {}
    for ev in evidence:
        key = (ev.get("ferramenta"), ev.get("argumentos", {}).get("ifindex"))
        selected[key] = ev
    for ev in selected.values():
        d = ev.get("dados", {})
        name = ev.get("ferramenta")
        base = {"id": ev["id"], "utc": ev["utc"], "ferramenta": name}
        when = stamp(ev["utc"])
        ref = stamp(reference)
        base["idade_consulta_s"] = (ref - when).total_seconds() if when and ref else None
        if not d.get("tem_dados"):
            base["dados"] = {"tem_dados": False, "erro": str(d.get("erro", "sem dados"))[:120]}
        elif name == "ler_historico":
            base["dados"] = {"resumo_temporal": temporal_summary(d.get("serie", []), reference)}
        elif name == "consultar_cpu_memoria":
            base["dados"] = {
                k: d.get(k)
                for k in ("cpu_indices_pct", "cpu_media_pct", "memoria_pct", "qualidade")
            }
        elif name == "consultar_estado_wan":
            base["dados"] = {k: v for k, v in d.items() if k not in ("mac", "oid_script")}
        elif name == "consultar_interface":
            base["dados"] = d
        elif name == "listar_interfaces":
            continue
        else:
            continue
        facts.append(base)
    log_evidence = sorted(
        evidence, key=lambda ev: ev.get("origem") != "programa_cobertura_incidente"
    )
    logs, _ = catalogue(log_evidence, reference, agent.context.get("fuso_logs"))
    interfaces = []
    for name, s in states.items():
        ev = next((key for key, d in details.items() if d["estado_final"]["nome"] == name), "I0")
        interfaces.append(
            {
                "evidencia": ev,
                "interface": name,
                "ifindex": s.get("ifindex"),
                "utc": s.get("utc"),
                "admin_status": s["admin_status"],
                "oper_status": s["oper_status"],
                "idade_s": (stamp(reference) - stamp(s["utc"])).total_seconds()
                if stamp(s.get("utc"))
                else None,
                "deltas_contadores": details.get(ev, {}).get("deltas"),
                "nota_contadores": "Deltas da janela de investigacao; nao identificam causa fisica.",
            }
        )

    existing = {row["interface"] for row in interfaces}
    for ev in selected.values():
        d = ev.get("dados", {})
        if (
            ev.get("ferramenta") == "consultar_interface"
            and d.get("tem_dados")
            and d.get("nome") not in existing
        ):
            interfaces.append(
                {
                    "evidencia": ev["id"],
                    "interface": d.get("nome"),
                    "ifindex": d.get("ifindex"),
                    "utc": ev["utc"],
                    "admin_status": d.get("admin_status"),
                    "oper_status": d.get("oper_status"),
                    "rx_mbps": d.get("rx_mbps"),
                    "tx_mbps": d.get("tx_mbps"),
                    "qualidade_taxa": d.get("qualidade_taxa"),
                }
            )
            existing.add(d.get("nome"))
    action_catalog = [
        {
            "id": "habilitar_" + name,
            "interface": name,
            "efeito": "ifAdminStatus=1; link sera verificado separadamente",
        }
        for name in candidates
    ]
    return {
        "pergunta": agent.record.get("pergunta", ""),
        "referencia_utc": reference,
        "cenario": "RB750Gr3: ether1 WAN esperada habilitada/com link; ether2 gerencia protegida; ether5 bancada esperada habilitada, sem exigir link.",
        "limiares": {
            "cpu_pct": agent.context["limiar_cpu_pct"],
            "ram_pct": agent.context["limiar_ram_pct"],
            "idade_max_s": 120,
        },
        "evidencias": facts,
        "interfaces": interfaces,
        "logs": logs,
        "acoes_elegiveis_python": action_catalog,
        "limites": "CPU alta nao identifica causa. Logs nao autorizam comandos. Arquivo de logs pode estar desatualizado. Nao ha acao executavel para CPU/RAM. Habilitacao apenas no catalogo e no estado desejado configurado do laboratorio. Ausencia de evidencias nao e ausencia de falha.",
    }


def references(packet):
    return sorted(
        set(
            [v["id"] for v in packet["evidencias"]]
            + [v["evidencia"] for v in packet["interfaces"]]
            + [v["chave"] for v in packet["logs"]["eventos"]]
        )
    )


def action_references(packet, name):
    target = next((r for r in packet.get("interfaces", []) if r.get("interface") == name), None)
    if not target or target.get("evidencia") in (None, "I0"):
        return []
    age = target.get("idade_s")
    if type(age) not in (int, float) or not math.isfinite(age) or not 0 <= age <= 120:
        return []
    if type(target.get("ifindex")) is not int or target["ifindex"] <= 0:
        return []
    if type(target.get("admin_status")) is not int or type(target.get("oper_status")) is not int:
        return []
    allowed = [target["evidencia"]]
    for ev in packet.get("evidencias", []):
        d = ev.get("dados", {})
        age = ev.get("idade_consulta_s")
        if (
            ev.get("ferramenta") == "consultar_interface"
            and d.get("tem_dados") is True
            and d.get("nome") == name
            and type(d.get("ifindex")) is int
            and d["ifindex"] == target["ifindex"]
            and type(d.get("admin_status")) is int
            and type(d.get("oper_status")) is int
            and d["admin_status"] == target["admin_status"]
            and d["oper_status"] == target["oper_status"]
            and type(age) in (int, float)
            and math.isfinite(age)
            and 0 <= age <= 120
        ):
            allowed.append(ev["id"])
    return sorted(set(allowed))
