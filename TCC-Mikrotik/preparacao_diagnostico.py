from politica_diagnostico import number

ESTADOS = ("normal", "alerta", "ausente", "invalido", "antigo", "tempo_inconsistente")


def metric_keys(config):
    return ["cpu_pct", "ram_pct"] + [
        "interface:" + n for n in config["interfaces_com_link_esperado"]
    ]


def model_context(objective, config, include_policy):
    selected = {f["metrica"]: f for f in objective["fatos"]}
    rows = []
    for key in metric_keys(config):
        fact = selected.get(key, {})
        rows.append(
            {
                "metrica": key,
                "valor": fact.get("valor"),
                "idade_da_leitura_segundos": fact.get("idade_s"),
                "instante_leitura_utc": fact.get("utc"),
                "evidencia": fact.get("evidencia"),
                "origem": fact.get("origem"),
            }
        )
    result = {
        "instante_referencia": objective["instante_referencia"],
        "criterios": {
            "limiar_cpu_pct": config["limiar_cpu_pct"],
            "limiar_ram_pct": config["limiar_ram_pct"],
            "idade_maxima_segundos": config["idade_maxima_s"],
            "oper_status_esperado": 1,
        },
        "leituras_selecionadas": rows,
    }
    if include_policy:
        result["perfil_python_fornecido"] = {
            "classificacao": objective["classificacao"],
            "avaliacao_metricas": expected_metric_states(objective, config),
        }
    return result


def expected_metric_states(objective, config):
    selected = {f["metrica"]: f for f in objective["fatos"]}
    result = {}
    for key in metric_keys(config):
        fact = selected.get(key, {})
        value, age = fact.get("valor"), fact.get("idade_s")
        if value is None:
            status = "ausente"
        elif not number(value) or not (
            0 <= value <= 100 if key.endswith("_pct") else value in range(1, 8)
        ):
            status = "invalido"
        elif not number(age) or age < 0:
            status = "tempo_inconsistente"
        elif age > config["idade_maxima_s"]:
            status = "antigo"
        elif key == "cpu_pct" and value >= config["limiar_cpu_pct"]:
            status = "alerta"
        elif key == "ram_pct" and value >= config["limiar_ram_pct"]:
            status = "alerta"
        elif key.startswith("interface:") and value != 1:
            status = "alerta"
        else:
            status = "normal"
        result[key] = status
    return result


def audit_report(report, objective, config):
    expected = expected_metric_states(objective, config)
    given = report["avaliacao_metricas"]
    checks = [
        {
            "metrica": key,
            "modelo": given[key],
            "perfil_python": value,
            "coincide": given[key] == value,
        }
        for key, value in expected.items()
    ]
    states = list(given.values())
    derived = (
        "suspeita"
        if "alerta" in states
        else "inconclusivo"
        if any(s != "normal" for s in states)
        else "sem_anomalia_evidente"
    )
    return {
        "metricas": checks,
        "acertos": sum(c["coincide"] for c in checks),
        "total": len(checks),
        "coerencia_interna_classificacao": report["classificacao"] == derived,
        "classificacao_derivada_dos_estados_do_modelo": derived,
        "texto_livre_validado_factualmente": False,
    }
