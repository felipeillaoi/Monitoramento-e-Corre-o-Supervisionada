import re


class LocalDiagnosticError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__(
            "Diagnostico bloqueado por verificacoes locais: " + ", ".join(e["tipo"] for e in errors)
        )


def install_verification_catalog(packet):
    packet["verificacoes_disponiveis"] = [
        {
            "id": "V" + str(i),
            "achado": finding["id"],
            "descricao": finding.get(
                "proxima_verificacao",
                "Repetir coleta e revisar o estado desejado antes de alterar a configuracao.",
            ),
        }
        for i, finding in enumerate(packet.get("problemas_observados", []))
    ]


def verification_errors(proposal, packet):
    if "verificacoes_disponiveis" not in packet:
        return []
    allowed = {r["id"] for r in packet["verificacoes_disponiveis"]}
    selected = proposal["proximas_verificacoes"]
    if (
        (allowed and not selected)
        or len(selected) != len(set(selected))
        or any(v not in allowed for v in selected)
    ):
        return [
            {
                "tipo": "verificacao_fora_do_catalogo",
                "campo": "proximas_verificacoes",
                "correcao": "Selecionar apenas IDs de verificacoes_disponiveis; nao escrever comando ou texto livre.",
            }
        ]
    return []


def _explicit_target_prefix(prefix):
    return (
        re.search(
            r"\b(?:estado(?:\s+(?:administrativo|operacional))?|valor|status)"
            r"\s+(?:desejado|esperado|alvo)\s*(?:[:=(]\s*)*$",
            prefix,
            re.I,
        )
        is not None
    )


def explicit_state_errors(proposal, packet):
    current = {r["interface"]: r for r in packet.get("fatos_conferiveis", {}).get("interfaces", [])}
    texts = []
    for key in ("resumo", "justificativa", "limitacoes"):
        values = proposal.get(key, [])
        values = [values] if isinstance(values, str) else values
        for i, text in enumerate(values):
            texts.append((key + "[" + str(i) + "]", text))
    for row in proposal.get("problemas_identificados", []):
        texts.append(("achado:" + row["id"], row["explicacao"]))
    errors = []
    for path, text in texts:
        for sentence in re.split(r"(?<=[.!?;])\s+", text):
            ports = set(re.findall(r"\bether[0-9]+\b", sentence.lower()))
            if len(ports) != 1:
                continue
            name = next(iter(ports))
            state = current.get(name)
            if state is None:
                continue
            for match in re.finditer(
                r"\b(admin_status|oper_status)\s*=\s*([0-9]+)\b", sentence, re.I
            ):
                prefix = sentence[: match.start()]
                if _explicit_target_prefix(prefix):
                    continue
                if re.search(r"\b(se|caso|apos|após|antes|anterior)\b", prefix, re.I):
                    continue
                if re.search(
                    r"(?:nao|não|nunca|diferente de)\s+(?:(?:e|é|tem|possui)\s+)?$", prefix, re.I
                ):
                    continue
                field = match[1].lower()
                value = int(match[2])
                actual = state.get(field)
                if type(actual) is int and value != actual:
                    errors.append(
                        {
                            "tipo": "estado_explicito_divergente",
                            "campo": path,
                            "trecho": sentence[:350],
                            "interface": name,
                            "metrica": field,
                            "valor_texto": value,
                            "valor_SNMP": actual,
                            "evidencia": state["evidencia"],
                            "correcao": f"Na leitura fornecida, {name} tem {field}={actual}; nao afirmar {field}={value} como estado observado.",
                        }
                    )
    return errors


def audit_proposal(proposal, packet):
    errors = verification_errors(proposal, packet) + explicit_state_errors(proposal, packet)
    if errors:
        raise LocalDiagnosticError(errors[:6])
