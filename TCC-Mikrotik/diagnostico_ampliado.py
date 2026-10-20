from __future__ import annotations
import math
from contexto_supervisionado import stamp
from investigacao_interfaces import expected_action

SERVICE_KEYS = ("dhcp:wan", "ipv4:wan", "rota:main", "dns:router", "disco")


def valid_pct(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100


def wan_signals(wan, reference):
    when = stamp(wan.get("utc"))
    ref = stamp(reference)
    if (
        not wan.get("tem_dados")
        or when is None
        or ref is None
        or not 0 <= (ref - when).total_seconds() <= 120
    ):
        return {key: "dados_indisponiveis" for key in SERVICE_KEYS}
    signals = {}
    count = wan["dhcp_count"]
    c = wan["dhcp"]
    if count < 0:
        signals["dhcp:wan"] = "dados_indisponiveis"
    elif count == 0:
        signals["dhcp:wan"] = "cliente_esperado_ausente"
    elif count > 1:
        signals["dhcp:wan"] = "clientes_ambiguos"
    elif c["disabled"] is True:
        signals["dhcp:wan"] = "cliente_desabilitado"
    elif c["invalid"] is True:
        signals["dhcp:wan"] = "cliente_marcado_invalido"
    elif type(c["disabled"]) is not bool or type(c["invalid"]) is not bool:
        signals["dhcp:wan"] = "dados_indisponiveis"
    elif (
        c["status"] not in ("bound", "renewing", "rebinding")
        or not c["address"]
        or c["address"].startswith("0.0.0.0/")
    ):
        signals["dhcp:wan"] = "sem_concessao_estavel:" + str(c["status"] or "nao_informado")
    for key, field in (
        ("ipv4:wan", "ipv4_count"),
        ("rota:main", "default_routes"),
        ("dns:router", "dns_servers"),
    ):
        if wan[field] < 0:
            signals[key] = "dados_indisponiveis"
        elif wan[field] == 0 and not (key == "dns:router" and wan["doh_configured"]):
            signals[key] = "ausente_nesta_leitura"
    if min(wan["free_hdd"], wan["total_hdd"]) < 0 or wan["total_hdd"] == 0:
        signals["disco"] = "dados_indisponiveis"
    elif wan["free_hdd"] < 1048576:
        signals["disco"] = "menos_de_1MiB_livre"
    return signals


def processor_signals(metrics, context):
    result = {}
    if (
        valid_pct(metrics.get("cpu_media_pct"))
        and metrics["cpu_media_pct"] < context["limiar_cpu_pct"]
    ):
        cores = metrics.get("cpu_indices_pct", {})
        if isinstance(cores, dict):
            for index, value in list(cores.items())[:32]:
                if (
                    isinstance(index, str)
                    and index.isdigit()
                    and valid_pct(value)
                    and value >= context["limiar_cpu_pct"]
                ):
                    result["cpu_indice:" + index] = "acima_do_limiar"
    return result


def build_findings(
    metrics, states, context, profile, reference, metric_ref, wan=None, wan_ref=None
):
    from monitoramento_continuo import current_signals

    signals = current_signals(metrics, states, context, profile, reference)
    signals.update(processor_signals(metrics, context))
    if wan is not None:
        signals.update(wan_signals(wan, reference))
    findings = []

    def add(code, key, title, evidence, check, action=None, quality="observado"):
        findings.append(
            {
                "id": "D" + str(len(findings)),
                "codigo": code,
                "chave_incidente": key,
                "problema": title,
                "qualidade": quality,
                "evidencias": [evidence],
                "correcao_disponivel": action,
                "proxima_verificacao": check,
                "causa_fisica": "nao_determinada",
            }
        )

    hot_reported = False
    for key, state in signals.items():
        if key in SERVICE_KEYS:
            continue
        if key in ("cpu", "ram"):
            label = "CPU media" if key == "cpu" else "RAM"
            field = "cpu_media_pct" if key == "cpu" else "memoria_pct"
            if state == "dados_indisponiveis":
                add(
                    "metrica_indisponivel",
                    key,
                    label + " sem leitura valida.",
                    metric_ref,
                    "Repetir coleta SNMP e verificar disponibilidade do OID.",
                    quality="inconclusivo",
                )
            else:
                add(
                    key + "_elevada",
                    key,
                    f"{label} em {metrics[field]:.2f}%, acima do limiar experimental.",
                    metric_ref,
                    "Confirmar persistencia e identificar a carga; a leitura nao identifica o processo causador.",
                )
        elif key.startswith("cpu_indice:"):
            if hot_reported:
                continue
            hot_reported = True
            index = key.split(":", 1)[1]
            add(
                "indice_cpu_elevado",
                key,
                f"Indice logico CPU {index} em {metrics['cpu_indices_pct'][index]:.2f}%, com media inferior ao limiar.",
                metric_ref,
                "Confirmar outras amostras e investigar a tarefa; indice logico nao comprova numero de nucleos fisicos.",
            )
        elif key.startswith("interface:"):
            name = key.split(":", 1)[1]
            s = states.get(name, {})
            if state == "dados_indisponiveis":
                add(
                    "estado_interface_indisponivel",
                    key,
                    name + " sem estado atual valido.",
                    "I0",
                    "Repetir inventario SNMP; nao interpretar ausencia de leitura como porta desabilitada.",
                    quality="inconclusivo",
                )
            elif s["admin_status"] != profile["interfaces"][name]["admin_desejado"]:
                action = (
                    "habilitar_" + name
                    if expected_action(s) == "habilitar_interface"
                    and profile["interfaces"][name]["propor_habilitacao"]
                    else None
                )
                add(
                    "estado_administrativo_divergente",
                    key,
                    f"{name}: admin_status={s['admin_status']}, diferente do estado desejado.",
                    "I0",
                    "Conferir contexto de manutencao. Uma mudanca administrativa nao demonstra a intencao do operador.",
                    action,
                )
            else:
                add(
                    "link_esperado_inativo",
                    key,
                    f"{name}: habilitada administrativamente, com oper_status={s['oper_status']} em vez de link up.",
                    "I0",
                    "Verificar cabo, parceiro remoto, configuracao e logs. Nao reabilitar uma porta ja habilitada.",
                )
    if wan is not None:
        ws = {key: value for key, value in signals.items() if key in SERVICE_KEYS}
        unknown = [key for key, v in ws.items() if v == "dados_indisponiveis"]
        if unknown:
            add(
                "observacao_wan_incompleta",
                "observacao:wan",
                "Observacao WAN incompleta para: " + ", ".join(unknown) + ".",
                wan_ref,
                "Conferir instalacao/permissoes do script e campos de qualidade. Nenhum valor ausente e considerado normal.",
                quality="inconclusivo",
            )
        v = ws.get("dhcp:wan")
        c = wan.get("dhcp") or {}
        if v == "cliente_esperado_ausente":
            add(
                "cliente_dhcp_ausente",
                "dhcp:wan",
                "Nenhum cliente DHCP configurado em ether1, embora esperado neste laboratorio.",
                wan_ref,
                "Conferir modo de enderecamento desejado; nao criar cliente ou presumir falha no servidor automaticamente.",
            )
        elif v == "clientes_ambiguos":
            add(
                "clientes_dhcp_ambiguos",
                "dhcp:wan",
                "Mais de um cliente DHCP encontrado em ether1.",
                wan_ref,
                "Identificar configuracao correta; nao escolher arbitrariamente um cliente para alterar.",
            )
        elif v == "cliente_desabilitado":
            add(
                "cliente_dhcp_desabilitado",
                "dhcp:wan",
                "Cliente DHCP de ether1 administrativamente desabilitado.",
                wan_ref,
                "Conferir manutencao e estado desejado; reabilitacao DHCP ainda nao faz parte do executor.",
            )
        elif v == "cliente_marcado_invalido":
            add(
                "cliente_dhcp_invalido",
                "dhcp:wan",
                "Cliente DHCP de ether1 marcado como invalid pelo RouterOS.",
                wan_ref,
                "Relacionar com estado da porta e configuracao. A flag nao determina sozinha a causa.",
            )
        elif v and v != "dados_indisponiveis":
            add(
                "dhcp_sem_concessao_estavel",
                "dhcp:wan",
                f"Cliente DHCP habilitado, com status={c.get('status') or 'nao informado'}, sem concessao estavel confirmada.",
                wan_ref,
                "Observar persistencia e trafego DHCP; pode haver negociacao em andamento. Nao afirmar defeito no servidor ou provedor.",
            )
        descriptions = {
            "ipv4:wan": (
                "wan_sem_ipv4",
                "Nenhum endereco IPv4 ativo observado em ether1.",
                "Verificar concessao DHCP e modo de enderecamento; nao comprova falha fim a fim.",
            ),
            "rota:main": (
                "rota_padrao_ausente",
                "Nenhuma rota IPv4 padrao ativa observada na tabela main.",
                "Conferir DHCP e rotas. Outras tabelas, IPv6 e rotas especificas nao foram avaliados.",
            ),
            "dns:router": (
                "dns_upstream_ausente",
                "Listas DNS servers/dynamic-servers vazias e nenhum DoH configurado.",
                "Verificar necessidade de resolucao no roteador. Entradas estaticas/FWD e DNS dos computadores nao foram testados.",
            ),
            "disco": (
                "pouco_espaco_livre",
                f"Armazenamento com menos de 1 MiB livre ({wan.get('free_hdd')} bytes).",
                "Identificar arquivos e crescimento; nenhuma remocao automatica foi implementada.",
            ),
        }
        for key, (code, title, check) in descriptions.items():
            if key in ws and ws[key] != "dados_indisponiveis":
                add(code, key, title, wan_ref, check)
    classification = (
        "desvios_observados"
        if any(f["qualidade"] == "observado" for f in findings)
        else "inconclusivo"
        if findings
        else "sem_desvio_no_escopo"
    )
    return {
        "referencia_utc": reference,
        "classificacao": classification,
        "sinais": signals,
        "problemas": findings,
        "limite": "Achados no escopo observado; nao certificam saude geral ou conectividade fim a fim. Causa raiz e intencao exigem evidencias adicionais.",
    }


def show_findings(report):
    print("\nAVALIACAO AMPLIADA:", report["classificacao"])
    print("ACHADOS VERIFICADOS DO MONITORAMENTO:")
    if not report["problemas"]:
        print("Nenhum desvio observado nos criterios avaliados.")
    for finding in report["problemas"]:
        print(f"  {finding['id']} [{finding['qualidade']}] {finding['problema']}")
        print(
            "    Correcao no catalogo:",
            finding["correcao_disponivel"] or "nenhuma; investigacao/recomendacao",
        )
        print("    Verificar:", finding["proxima_verificacao"])
