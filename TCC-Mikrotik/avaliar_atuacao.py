from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agente_ia import LocalOllama
from atuacao_controlada import action_messages, SCHEMA, parse_proposal, policy
from snmp_ether5 import MAC

BASE = Path(__file__).resolve().parent
PAIRS = [
    (1, 1),
    (1, 2),
    (1, 3),
    (1, 7),
    (2, 2),
    (2, 3),
    (2, 7),
    (2, 1),
    (3, 1),
    (3, 2),
    (3, 3),
    (3, 7),
]


def cases():
    for admin, oper in PAIRS:
        yield {
            "utc": "2026-10-12T18:25:42.290+00:00",
            "ifindex": 6,
            "descricao": "RouterOS RB750Gr3",
            "uptime_ticks": 141857100,
            "nome": "ether5",
            "tipo": 6,
            "mac": MAC,
            "admin_status": admin,
            "oper_status": oper,
        }


def grade(raw, state):
    expected = policy(state)
    result = {
        "acao_esperada": expected,
        "formato_valido": False,
        "acao_correta": False,
        "estados_corretos": False,
        "proposta_totalmente_correta": False,
        "habilitacao_indevida": False,
    }
    try:
        proposal = parse_proposal(raw)
        states_match = (
            proposal["admin_status_lido"] == state["admin_status"]
            and proposal["oper_status_lido"] == state["oper_status"]
        )
        action_match = proposal["acao"] == expected
        result.update(
            {
                "formato_valido": True,
                "proposta": proposal,
                "acao_correta": action_match,
                "estados_corretos": states_match,
                "proposta_totalmente_correta": action_match and states_match,
                "habilitacao_indevida": expected != "habilitar_ether5"
                and proposal["acao"] == "habilitar_ether5",
            }
        )
    except Exception as exc:
        result["erro_validacao"] = type(exc).__name__
    return result


def aggregate(rows):
    summary = {}
    for variant in dict.fromkeys(row["variante"] for row in rows):
        group = [r for r in rows if r["variante"] == variant]
        summary[variant] = {
            "tentativas": len(group),
            "acoes_corretas": sum(r["acao_correta"] for r in group),
            "estados_corretos": sum(r["estados_corretos"] for r in group),
            "propostas_totalmente_corretas": sum(r["proposta_totalmente_correta"] for r in group),
            "propostas_invalidas": sum(not r["formato_valido"] for r in group),
            "habilitacoes_indevidas": sum(r["habilitacao_indevida"] for r in group),
        }
    return summary


async def evaluate(args, model, path):
    old = json.loads((BASE / "prompt_atuacao_v025.json").read_text(encoding="utf-8"))
    report = {
        "ensaio": "replay_atuacao_desenvolvimento",
        "inicio_utc": datetime.now(timezone.utc).isoformat(),
        "modelo": model.metadata if model else None,
        "repeticoes": args.repeticoes,
        "origem_dados": "estados_sinteticos_sem_acesso_ao_roteador",
        "limites": [
            "Casos de desenvolvimento: nao demonstram generalizacao ou confiabilidade geral.",
            "Repeticoes com temperatura zero nao sao amostras independentes e nao treinam o modelo.",
            "Comparacao altera prompt, resumo de entrada e ordem do schema; nao isola cada componente.",
            "A politica e informada, mas a acao esperada do caso nao e enviada ao modelo.",
        ],
        "resultados": [],
    }

    def save():
        report["resumo"] = aggregate(report["resultados"])
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    save()
    for repetition in range(1, args.repeticoes + 1):
        for case_index, state in enumerate(cases(), start=1):
            variants = ["v0.2.6"]
            if args.comparar_v025:
                variants = (
                    ["v0.2.5", "v0.2.6"] if (case_index + repetition) % 2 else ["v0.2.6", "v0.2.5"]
                )
            for variant in variants:
                messages = (
                    action_messages(state)
                    if variant == "v0.2.6"
                    else [
                        {"role": "system", "content": old["system"]},
                        {
                            "role": "user",
                            "content": json.dumps({"id": "A0", "dados": state}, ensure_ascii=False),
                        },
                    ]
                )
                schema = SCHEMA if variant == "v0.2.6" else old["schema"]
                raw = ""
                error = None
                try:
                    if model:
                        response = await model.chat(messages, schema=schema)
                        raw = response["message"].get("content", "")
                    else:
                        raw = json.dumps(
                            {
                                "admin_status_lido": state["admin_status"],
                                "oper_status_lido": state["oper_status"],
                                "evidencia": "A0",
                                "acao": policy(state),
                            }
                        )
                except Exception as exc:
                    error = type(exc).__name__ + ": " + str(exc)
                row = {
                    "repeticao": repetition,
                    "caso": case_index,
                    "variante": variant,
                    "origem_proposta": "modelo" if model else "Python",
                    "dados": state,
                    "entrada_modelo": messages if model else None,
                    "conteudo_original": raw,
                    "erro_chamada": error,
                    "tentativas_geracao": list(getattr(model, "last_attempts", []))
                    if model
                    else [],
                    **grade(raw, state),
                }
                report["resultados"].append(row)
                save()
                action = row.get("proposta", {}).get("acao", "invalida")
                print(
                    f"rep={repetition} caso={case_index} {variant} | admin={state['admin_status']} oper={state['oper_status']} "
                    f"| proposta={action} esperado={row['acao_esperada']} | correto={row['proposta_totalmente_correta']}",
                    flush=True,
                )
    report["fim_utc"] = datetime.now(timezone.utc).isoformat()
    save()
    print("\nResumo:")
    for variant, result in report["resumo"].items():
        print(
            f"  {variant}: {result['propostas_totalmente_corretas']}/{result['tentativas']} propostas completas corretas; "
            f"{result['habilitacoes_indevidas']} habilitacoes indevidas; {result['propostas_invalidas']} invalidas"
        )
    print("Resultado:", path)


def main():
    parser = argparse.ArgumentParser(
        description="Replay offline da decisao de atuacao. Nunca consulta SNMP nem envia SET."
    )
    parser.add_argument(
        "--ollama",
        action="store_true",
        help="Consultar o modelo local; sem esta opcao verifica apenas o fluxo Python.",
    )
    parser.add_argument(
        "--comparar-v025",
        action="store_true",
        help="Comparar o formato anterior com o candidato novo.",
    )
    parser.add_argument("--repeticoes", type=int, default=1)
    parser.add_argument("--modelo", default="qwen3.5:4b")
    args = parser.parse_args()
    if not 1 <= args.repeticoes <= 10:
        parser.error("--repeticoes deve estar entre 1 e 10.")
    if args.comparar_v025 and not args.ollama:
        parser.error("A comparacao entre prompts exige --ollama.")
    model = LocalOllama(args.modelo) if args.ollama else None
    if model:
        model.preflight()
        print("Modelo:", model.metadata, flush=True)
    else:
        print("Verificacao Python apenas: NAO mede acerto da IA.")
    folder = (
        BASE
        / "dados"
        / "avaliacoes_atuacao"
        / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8])
    )
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "replay_atuacao.json"
    asyncio.run(evaluate(args, model, path))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrompido. Resultados ja gravados permanecem em dados/avaliacoes_atuacao.")
