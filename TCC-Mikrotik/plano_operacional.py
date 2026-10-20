import copy
import json
from investigacao_interfaces import validate_plan, PORTS


def bind_plan(packet, preparation, states, details, interface=None):
    result = copy.deepcopy(packet)
    if interface is None:
        result["objetivo_operador"] = {
            "tipo": "monitoramento",
            "nota": "Analise e recomendacoes sem objetivo de restauracao configurado.",
        }
        result["acoes_elegiveis_python"] = []
        return result
    if interface not in ("ether1", "ether5"):
        raise ValueError("Objetivo de restauracao permite somente ether1 ou ether5.")
    if preparation.get("resultado") not in (
        "simulacao_habilitacao_proposta_sem_SET",
        "sem_correcao_administrativa_indicada",
    ):
        raise ValueError("Nao ha plano Qwen de preparacao valido para vincular ao objetivo.")
    original = preparation.get("plano_IA")
    plan, candidates = validate_plan(json.dumps(original, ensure_ascii=False), states, details)
    row = next(r for r in plan["avaliacoes"] if r["interface"] == interface)
    action = (
        "habilitar_" + interface
        if row["acao"] == "habilitar_interface"
        else "nenhuma"
        if row["acao"] == "nenhuma"
        else "investigar"
    )
    if action.startswith("habilitar_") and interface not in candidates:
        raise ValueError("Acao do plano nao consta nas candidatas autorizadas.")
    result["objetivo_operador"] = {
        "tipo": "restauracao_administrativa",
        "interface": interface,
        "admin_status_desejado": 1,
        "link_exigido": PORTS[interface]["link_esperado"],
        "nota": "O operador configurou o objetivo. Propor a restauracao nao e executa-la; consentimento sera pedido apos parecer aprovado.",
    }
    result["plano_operacional_qwen"] = {
        "origem": "plano_IA_etapa_investigacao",
        "acao": action,
        "interface": interface,
        "ifindex": states[interface]["ifindex"],
        "evidencia": row["evidencia"],
        "avaliacao_original_qwen": copy.deepcopy(row),
        "nota": "Acao original do Qwen preservada. A etapa de redacao explica esta acao; nao e uma segunda escolha operacional.",
    }
    result["acoes_elegiveis_python"] = [
        a
        for a in result.get("acoes_elegiveis_python", [])
        if a["interface"] == interface and a["id"] == action
    ]
    if action.startswith("habilitar_") and not result["acoes_elegiveis_python"]:
        raise ValueError("Catalogo nao contem a acao operacional escolhida.")
    return result


def bound_action(packet):
    core = packet.get("plano_operacional_qwen")
    if core is None:
        return None
    action = core.get("acao")
    if action not in ("nenhuma", "investigar", "habilitar_ether1", "habilitar_ether5"):
        raise ValueError("Acao do plano operacional desconhecida.")
    return action


def bind_detected_plan(packet, preparation, states, details, profile, eligible_names=None):
    allowed = set(eligible_names) if eligible_names is not None else set(PORTS)
    desired = profile["interfaces"]
    eligible = [
        a["interface"]
        for a in packet.get("acoes_elegiveis_python", [])
        if a["interface"] in allowed
        and desired[a["interface"]]["admin_desejado"] == 1
        and desired[a["interface"]]["propor_habilitacao"]
    ]
    selected = next((name for name in PORTS if name in eligible), None)
    if selected is not None:
        result = bind_plan(packet, preparation, states, details, selected)
    else:
        result = copy.deepcopy(packet)
        result["acoes_elegiveis_python"] = []
        result.pop("plano_operacional_qwen", None)
    result["objetivo_operador"] = {
        "tipo": "manter_estado_desejado",
        "interfaces": copy.deepcopy(desired),
        "interface": selected,
        "admin_status_desejado": 1 if selected else None,
        "link_exigido": desired[selected]["link_exigido"] if selected else None,
        "nota": "Perfil configurado pelo operador; desvio descoberto por SNMP. Propor nao e executar. Exige revisao e consentimento posterior.",
    }
    result["acoes_adiadas_para_outro_ciclo"] = [name for name in eligible if name != selected]
    return result
