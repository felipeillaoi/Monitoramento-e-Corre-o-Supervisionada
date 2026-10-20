import argparse
import asyncio
import copy
import json
from getpass import getpass
from pathlib import Path
from datetime import datetime, timezone
import uuid
import hashlib
from fatos_diagnostico import compile_facts
from contexto_supervisionado import fingerprint, references
from revisor_gpt import (
    GPTReviewer,
    DEFAULT_MODEL,
    validate_review,
    validate_factual_quotes,
    resolve_factual_quote,
)


def cases():
    ref = "2026-10-19T16:38:00+00:00"
    wan = {
        "tem_dados": True,
        "utc": ref,
        "qualidade": "parcial",
        "dhcp_count": 1,
        "dhcp": {"disabled": True, "invalid": None, "status": "stopped", "address": ""},
        "ipv4_count": 0,
        "default_routes": 0,
        "dns_servers": 0,
        "doh_configured": False,
    }
    p = {
        "referencia_utc": ref,
        "pergunta": "Identifique os problemas observados sem inferir causa fisica.",
        "cenario": "Laboratorio sintetico: ether1 e ether2 com link esperado; ether5 sem exigencia de link.",
        "objetivo_operador": {"tipo": "manter_estado_desejado"},
        "acoes_elegiveis_python": [],
        "evidencias": [
            {
                "id": "E1",
                "utc": ref,
                "idade_consulta_s": 0,
                "ferramenta": "consultar_estado_wan",
                "dados": wan,
            }
        ],
        "interfaces": [
            {
                "interface": name,
                "evidencia": "I0",
                "admin_status": 1,
                "oper_status": oper,
                "idade_s": 0,
            }
            for name, oper in [("ether1", 1), ("ether2", 1), ("ether5", 2)]
        ],
        "logs": {"eventos": []},
        "problemas_observados": [
            {
                "id": "D0",
                "codigo": "cliente_dhcp_desabilitado",
                "problema": "Cliente DHCP desabilitado em ether1.",
                "evidencias": ["E1"],
            },
            {
                "id": "D1",
                "codigo": "wan_sem_ipv4",
                "problema": "Sem IPv4 ativo em ether1.",
                "evidencias": ["E1"],
            },
            {
                "id": "D2",
                "codigo": "rota_padrao_ausente",
                "problema": "Sem rota padrao IPv4 ativa em main.",
                "evidencias": ["E1"],
            },
            {
                "id": "D3",
                "codigo": "dns_upstream_ausente",
                "problema": "DNS upstream vazio e DoH nao configurado.",
                "evidencias": ["E1"],
            },
        ],
    }
    p["fatos_conferiveis"] = compile_facts(p)
    good = {
        "resumo": "Cliente DHCP desabilitado em ether1, com link up, sem IPv4 ativo, rota padrao IPv4/main e DNS upstream configurado.",
        "acao": "investigar",
        "justificativa": "Investigar e avaliar reabilitacao do cliente conforme estado desejado; nao ha correcao DHCP no catalogo.",
        "evidencias": ["E1", "I0"],
        "hipoteses": [],
        "limitacoes": [
            "invalid=null e desconhecido. Nao foram testados DNS dos PCs nem conectividade fim a fim."
        ],
        "proximas_verificacoes": [
            "Conferir se a desabilitacao do cliente DHCP faz parte de manutencao."
        ],
        "problemas_identificados": [
            {"id": f["id"], "explicacao": f["problema"]} for f in p["problemas_observados"]
        ],
    }
    result = [
        {
            "nome": "diagnostico_coerente",
            "packet": copy.deepcopy(p),
            "proposta": copy.deepcopy(good),
            "esperado": "aprovar",
        }
    ]
    for name, text in [
        ("confunde_link_com_ip", "A ether1 esta sem link fisico."),
        (
            "rota_padrao_vira_tabela_vazia",
            "A tabela main esta vazia e nao existe qualquer caminho externo.",
        ),
        ("dns_do_pc_sem_teste", "Os computadores estao incapazes de resolver nomes DNS."),
        (
            "defeito_fisico_inventado",
            "A ether5 apresenta defeito fisico comprovado porque oper_status=2.",
        ),
        ("null_vira_false", "invalid=null significa invalid=false e confirma cliente valido."),
    ]:
        proposal = copy.deepcopy(good)
        proposal["resumo"] = text
        result.append(
            {"nome": name, "packet": copy.deepcopy(p), "proposta": proposal, "esperado": "rejeitar"}
        )
    return result


def score_case(case, review):
    opinion = review.get("parecer") or {}
    matching = opinion.get("decisao") == case["esperado"]
    usable = review.get("status") == "concluida"
    ok = (
        usable
        and matching
        and (
            case["esperado"] == "aprovar"
            or opinion.get("avaliacao_factual") == "erros_identificados"
        )
    )
    extras = []
    target_found = None
    if usable and case["esperado"] == "rejeitar":
        target = " ".join(case["proposta"]["resumo"].split())
        target_found = False
        for e in opinion.get("erros_factuais", []):
            if resolve_factual_quote(e["trecho"], case["proposta"])["texto"] == target:
                target_found = True
            else:
                extras.append(e["trecho"])
        ok = ok and target_found
    return {
        "caso": case["nome"],
        "esperado": case["esperado"],
        "decisao_concordante": matching,
        "parecer_utilizavel": usable,
        "erro_alvo_identificado": target_found,
        "acerto": ok,
        "criticas_adicionais_para_revisao_manual": extras,
        "revisao": review,
    }


def print_row(row):
    review = row["revisao"]
    opinion = review.get("parecer") or {}
    print(
        row["caso"],
        "| esperado:",
        row["esperado"],
        "| decisao:",
        opinion.get("decisao", "nao disponivel"),
        "| status:",
        review["status"],
        "| factual:",
        opinion.get("avaliacao_factual", "nao disponivel"),
        "| decisao concordante:",
        row["decisao_concordante"],
        "| parecer utilizavel:",
        row["parecer_utilizavel"],
    )
    if row["esperado"] == "rejeitar":
        print("  Erro alvo identificado:", row["erro_alvo_identificado"])
    if review.get("motivo_inconsistencia"):
        print("  Motivo:", review["motivo_inconsistencia"])
    if row["criticas_adicionais_para_revisao_manual"]:
        print(
            "  Criticas adicionais exigem revisao manual:",
            len(row["criticas_adicionais_para_revisao_manual"]),
        )


def reprocess(path):
    data = Path(path).read_bytes()
    if len(data) > 10_000_000:
        raise ValueError("Registro excede 10 MB.")
    text = data.decode("utf-8-sig")
    start = text.find("{")
    if start < 0:
        raise ValueError("Nenhum JSON encontrado.")
    original, end = json.JSONDecoder().raw_decode(text[start:])
    if text[start + end :].strip():
        raise ValueError("Texto extra apos JSON; forneca somente o registro.")
    if not isinstance(original, dict) or not isinstance(original.get("casos"), list):
        raise ValueError("Registro fora do formato esperado.")
    known = {c["nome"]: c for c in cases()}
    rows = []
    seen = set()
    for previous in original["casos"]:
        name = previous.get("caso")
        if name not in known or name in seen:
            raise ValueError("Caso desconhecido ou repetido no registro.")
        seen.add(name)
        case = known[name]
        p, doc = case["packet"], case["proposta"]
        pid = fingerprint({"contexto": p, "proposta": doc})
        ids = references(p)
        review = copy.deepcopy(previous["revisao"])
        review["validacao_anterior"] = {
            "status": review.get("status"),
            "motivo_inconsistencia": review.get("motivo_inconsistencia"),
        }
        review["metodo_validacao"] = (
            "reprocessamento_local; resposta original reutilizada; nenhuma chamada API"
        )
        try:
            if review.get("proposta_id") != pid:
                raise ValueError("Hash nao corresponde ao caso sintetico conhecido.")
            opinion = json.loads(review["conteudo_original"])
            validate_review(opinion, pid, ids, doc["acao"], factual_required=True)
            normalized = []
            validate_factual_quotes(opinion, doc, normalized)
            review.update(status="concluida", parecer=opinion, normalizacoes_trechos=normalized)
            review.pop("motivo_inconsistencia", None)
        except (ValueError, TypeError, KeyError) as exc:
            review.update(
                status="reprocessamento_invalido", parecer=None, motivo_inconsistencia=str(exc)
            )
        row = score_case(case, review)
        rows.append(row)
        print_row(row)
    return rows, {
        "arquivo_origem": str(path),
        "sha256_origem": hashlib.sha256(data).hexdigest(),
        "versao_origem": original.get("versao"),
        "novas_chamadas_API": 0,
        "registro_original_preservado": True,
    }


def save_report(rows, model, source=None):
    folder = Path(__file__).resolve().parent / "dados" / "avaliacoes_revisor_factual"
    folder.mkdir(parents=True, exist_ok=True)
    suffix = "_reprocessado" if source else ""
    path = folder / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + uuid.uuid4().hex[:8]
        + suffix
        + ".json"
    )
    report = {
        "versao": "0.5.5",
        "tipo": "reprocessamento local sem API" if source else "casos sinteticos; sem SNMP/SET",
        "modelo": model,
        "acertos": sum(r["acerto"] for r in rows),
        "decisoes_concordantes": sum(r["decisao_concordante"] for r in rows),
        "pareceres_utilizaveis": sum(r["parecer_utilizavel"] for r in rows),
        "total": len(rows),
        "casos": rows,
        "erros_alvo_identificados": sum(r["erro_alvo_identificado"] is True for r in rows),
        "casos_negativos": sum(r["esperado"] == "rejeitar" for r in rows),
        "casos_com_criticas_adicionais": sum(
            bool(r["criticas_adicionais_para_revisao_manual"]) for r in rows
        ),
        "limite": "Decisao concordante e formato valido nao provam qualidade de toda critica. Seis casos direcionados nao estimam qualidade geral.",
    }
    if source:
        report["origem_reprocessamento"] = source
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Decisoes concordantes:", report["decisoes_concordantes"], "/", report["total"])
    print("Pareceres utilizaveis:", report["pareceres_utilizaveis"], "/", report["total"])
    print(
        "Criterios decisao/formato/erro-alvo:",
        report["acertos"],
        "/",
        report["total"],
        "| Registro:",
        path,
    )
    return path


async def run(args):
    if args.reprocessar:
        rows, source = reprocess(args.reprocessar)
        save_report(rows, "modelo do registro original; sem nova consulta", source)
        return
    suite = cases()
    if not args.api:
        print(
            "6 casos sinteticos preparados. Nenhuma chamada API; qualidade do GPT NAO foi medida."
        )
        print("Para avaliar o modelo real: python avaliar_revisor_factual.py --api")
        return
    print(
        "6 revisoes reais pela API, com dados SINTETICOS; pode gerar cobranca de tokens. Sem SNMP/SET."
    )
    key = getpass("Chave API OpenAI (oculta, somente em memoria): ")
    if not key:
        raise ValueError("Chave ausente; nenhum teste remoto executado.")
    reviewer = GPTReviewer(key, model=args.modelo_gpt, timeout=args.timeout_gpt)
    rows = []
    for case in suite:
        p, doc = case["packet"], case["proposta"]
        pid = fingerprint({"contexto": p, "proposta": doc})
        review = await reviewer.review(p, doc, pid, references(p))
        row = score_case(case, review)
        rows.append(row)
        print_row(row)
    save_report(rows, args.modelo_gpt)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seis casos SINTETICOS de revisao factual. Sem SNMP/SET. API so com --api."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--api", action="store_true")
    mode.add_argument(
        "--reprocessar",
        type=Path,
        help="Revalida respostas salvas, sem chave nem chamada API; preserva o original.",
    )
    parser.add_argument("--modelo-gpt", default=DEFAULT_MODEL)
    parser.add_argument("--timeout-gpt", type=int, default=20)
    try:
        asyncio.run(run(parser.parse_args()))
    except (KeyboardInterrupt, EOFError):
        raise SystemExit("Interrompido.")
    except ValueError as exc:
        raise SystemExit(str(exc))
