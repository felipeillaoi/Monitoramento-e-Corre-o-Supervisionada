from __future__ import annotations
import json
import math
from datetime import datetime
from pathlib import Path

DEFAULT_CONTEXT = Path(__file__).with_name("contexto_lab.json")


def load_context(path=DEFAULT_CONTEXT):
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    for key in ("limiar_cpu_pct", "limiar_ram_pct"):
        v = config.get(key)
        if not number(v) or not 0 < v <= 100:
            raise ValueError(f"Configuracao invalida: {key}")
    age = config.get("idade_maxima_s")
    if not number(age) or not 1 <= age <= 3600:
        raise ValueError("Configuracao invalida: idade_maxima_s")
    names = config.get("interfaces_com_link_esperado")
    if (
        not isinstance(names, list)
        or not names
        or any(not isinstance(n, str) or not n for n in names)
    ):
        raise ValueError("Informe interfaces_com_link_esperado.")
    optional = config.get("interfaces_sem_exigencia_de_link", [])
    if not isinstance(optional, list) or any(not isinstance(n, str) for n in optional):
        raise ValueError("Lista de interfaces sem exigencia invalida.")
    if len(set(names)) != len(names) or set(names) & set(optional):
        raise ValueError("Interfaces repetidas ou com expectativas conflitantes.")
    return config


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def stamp(value):
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo is not None else None
    except (ValueError, TypeError):
        return None


def assess(evidence, config, reference):
    moment = stamp(reference)
    if moment is None:
        raise ValueError("Referencia temporal deve incluir fuso horario.")
    selected = {}
    limitations = []
    informational = []
    historical_ages = []

    def put(key, value, timestamp, eid, source, field):
        dt = stamp(timestamp)
        if dt is None:
            return
        item = {
            "valor": value,
            "utc": timestamp,
            "evidencia": eid,
            "origem": source,
            "campo": field,
            "idade_s": round((moment - dt).total_seconds(), 3),
        }
        old = selected.get(key)

        if old is None or dt >= stamp(old["utc"]):
            selected[key] = item

    for ev in evidence:
        d = ev.get("dados", {})
        eid, when = ev.get("id"), ev.get("utc")
        tool = ev.get("ferramenta")
        if not isinstance(eid, str) or not isinstance(d, dict):
            continue
        if tool == "ler_historico" and d.get("serie"):
            candidates = [row for row in d["serie"] if stamp(row.get("utc")) is not None]
            if candidates:
                row = max(candidates, key=lambda r: stamp(r["utc"]))
                date = row["utc"]
                historical_ages.append(
                    {"evidencia": eid, "idade_s": round((moment - stamp(date)).total_seconds(), 3)}
                )
                put("cpu_pct", row.get("cpu_pct"), date, eid, "historico", "serie.cpu_pct")
                put("ram_pct", row.get("ram_pct"), date, eid, "historico", "serie.ram_pct")
                for port in d.get("interfaces_ultimo_ciclo_max16", []):
                    name = port.get("nome")
                    if name:
                        put(
                            "interface:" + name,
                            port.get("oper_status"),
                            date,
                            eid,
                            "historico",
                            "interfaces.oper_status",
                        )
        elif tool == "consultar_cpu_memoria":
            put("cpu_pct", d.get("cpu_media_pct"), when, eid, "consulta_snmp", "cpu_media_pct")
            put("ram_pct", d.get("memoria_pct"), when, eid, "consulta_snmp", "memoria_pct")
        elif tool == "consultar_interface":
            if d.get("nome"):
                put(
                    "interface:" + d["nome"],
                    d.get("oper_status"),
                    when,
                    eid,
                    "consulta_snmp",
                    "oper_status",
                )
        if "estimado_sem_marcador" in json.dumps(d, ensure_ascii=False):
            limitations.append(
                "Taxas estimadas sem marcador de descontinuidade: alguns resets de contadores podem nao ser detectados. Isso nao e evidencia de reset ou defeito."
            )
        if d.get("contadores_acumulados"):
            informational.append(
                {
                    "evidencia": eid,
                    "contadores_acumulados": d["contadores_acumulados"],
                    "nota": "Totais acumulados nao localizam incidentes no tempo.",
                }
            )

    facts, alerts, missing = [], [], []
    required = ["cpu_pct", "ram_pct"] + [
        "interface:" + n for n in config["interfaces_com_link_esperado"]
    ]
    for key in required:
        item = selected.get(key)
        value = item.get("valor") if item else None
        age = item.get("idade_s") if item else None
        valid_value = number(value) and (
            0 <= value <= 100 if key.endswith("_pct") else value in range(1, 8)
        )
        fresh = age is not None and 0 <= age <= config["idade_maxima_s"]
        if not valid_value or not fresh:
            missing.append(key)
            if item:
                facts.append({"metrica": key, **item, "utilizavel": False})
            continue
        fact = {"metrica": key, **item, "utilizavel": True}
        facts.append(fact)
        if key == "cpu_pct" and value >= config["limiar_cpu_pct"]:
            alerts.append(
                {
                    "codigo": "cpu_elevada",
                    "evidencia": item["evidencia"],
                    "metrica": key,
                    "valor": value,
                    "limiar": config["limiar_cpu_pct"],
                    "descricao": "CPU acima do limiar experimental nesta leitura; duracao e causa nao determinadas.",
                }
            )
        elif key == "ram_pct" and value >= config["limiar_ram_pct"]:
            alerts.append(
                {
                    "codigo": "ram_elevada",
                    "evidencia": item["evidencia"],
                    "metrica": key,
                    "valor": value,
                    "limiar": config["limiar_ram_pct"],
                    "descricao": "RAM acima do limiar experimental nesta leitura; causa nao determinada.",
                }
            )
        elif key.startswith("interface:") and value != 1:
            alerts.append(
                {
                    "codigo": "link_esperado_nao_ativo",
                    "evidencia": item["evidencia"],
                    "metrica": key,
                    "valor": value,
                    "esperado": 1,
                    "descricao": "Interface configurada como esperada ativa esta em outro estado; motivo nao determinado.",
                }
            )
    classification = (
        "suspeita" if alerts else "inconclusivo" if missing else "sem_anomalia_evidente"
    )
    if missing:
        limitations.append("Sem valor valido e recente para: " + ", ".join(missing) + ".")
    limitations.append(
        "Escopo: limiares de CPU/RAM e estado operacional das interfaces esperadas. Nao certifica saude geral, ausencia de crash, estabilidade prolongada ou conectividade fim a fim."
    )
    limitations.append(
        "Erros, descartes e variacoes de trafego nao integram a classificacao automatica deste perfil; exigem investigacao especifica."
    )
    return {
        "perfil": config["perfil"],
        "instante_referencia": reference,
        "classificacao": classification,
        "fatos": facts,
        "alertas": alerts,
        "pendencias": missing,
        "historicos": historical_ages,
        "observacoes": informational,
        "limitacoes": list(dict.fromkeys(limitations)),
        "limiares_experimentais": {
            "cpu_pct": config["limiar_cpu_pct"],
            "ram_pct": config["limiar_ram_pct"],
        },
        "interfaces_com_link_esperado": config["interfaces_com_link_esperado"],
    }


def render_verified(assessment):
    cls = assessment["classificacao"]
    descriptions = []
    refs = []
    for fact in assessment["fatos"]:
        if not fact["utilizavel"]:
            continue
        key, value = fact["metrica"], fact["valor"]
        if key == "cpu_pct":
            descriptions.append(f"CPU {value:.2f}%")
        elif key == "ram_pct":
            descriptions.append(f"RAM {value:.2f}%")
        else:
            descriptions.append(
                f"{key.split(':', 1)[1]}: "
                + ("ativa" if value == 1 else f"estado operacional {int(value)}")
            )
        refs.append(fact["evidencia"])
    lead = {
        "sem_anomalia_evidente": "Sem anomalia evidente nos criterios avaliados.",
        "suspeita": "Ha indicadores que exigem investigacao nos criterios avaliados.",
        "inconclusivo": "Dados insuficientes ou antigos para concluir neste perfil.",
    }[cls]
    next_checks = []
    if assessment["pendencias"]:
        next_checks.append(
            "Obter leituras validas e recentes de: " + ", ".join(assessment["pendencias"]) + "."
        )
    for alert in assessment["alertas"]:
        next_checks.append("Confirmar em novas amostras e investigar: " + alert["descricao"])
    if not next_checks:
        next_checks.append(
            "Manter a coleta para observar mudancas ao longo do tempo; nenhuma correcao indicada por este perfil nesta avaliacao."
        )
    return {
        "classificacao": cls,
        "resumo": lead + (" " + "; ".join(descriptions) + "." if descriptions else ""),
        "evidencias": list(dict.fromkeys(refs)),
        "hipoteses": [],
        "limitacoes": assessment["limitacoes"],
        "proximas_verificacoes": next_checks,
        "origem": "perfil_objetivo_python",
        "alertas": assessment["alertas"],
    }
