import argparse
import json
from collections import Counter
from pathlib import Path


def summarize(paths):
    statuses = Counter()
    reviews = Counter()
    opinions = Counter()
    modes = Counter()
    invalid = []
    sent = responses = confirmed = consents = 0
    rows = []
    for path in paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc.get("arquitetura") != "qwen_gpt_humano_snmp":
                continue
            s = doc.get("supervisao", {})
            events = s.get("eventos", [])
            statuses[s.get("resultado", doc.get("status_execucao", "etapa_nao_concluida"))] += 1
            r = s.get("revisao_gpt", {})
            reviews[r.get("status", "nao_executada")] += 1
            if r.get("parecer"):
                opinions[r["parecer"]["decisao"]] += 1
            modes[s.get("modo", "nao_identificado")] += 1
            sent += sum(e["evento"] == "SET_a_enviar" for e in events)
            responses += sum(
                e["evento"] == "resposta_SET" and e.get("resultado") == "aceito" for e in events
            )
            confirmed += int(s.get("resultado") == "habilitacao_confirmada")
            consents += sum(
                e["evento"] == "decisao_operador" and e.get("aprovou", False) for e in events
            )
            rows.append(
                {
                    "arquivo": path.name,
                    "resultado": s.get("resultado", doc.get("status_execucao")),
                    "revisao": r.get("status"),
                }
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            invalid.append(path.name)
    return {
        "registros": len(rows),
        "modos": dict(modes),
        "resultados": dict(statuses),
        "status_API": dict(reviews),
        "pareceres_GPT": dict(opinions),
        "aprovacoes_humanas": consents,
        "intencoes_SET": sent,
        "respostas_SET_aceitas": responses,
        "habilitacoes_confirmadas": confirmed,
        "arquivos_invalidos": invalid,
        "arquivos": rows,
        "limite": "Concordancia e confirmacao administrativa nao comprovam qualidade geral do diagnostico nem conectividade fim a fim.",
    }


def main():
    p = argparse.ArgumentParser(
        description="Resumo dos registros v0.4.0. Nao mede acuracia factual dos modelos."
    )
    p.add_argument("--ultimos", type=int, default=20)
    p.add_argument(
        "--pasta",
        type=Path,
        default=Path(__file__).resolve().parent / "dados" / "analises_supervisionadas",
    )
    a = p.parse_args()
    if a.ultimos < 1:
        p.error("--ultimos deve ser positivo.")
    paths = sorted(a.pasta.glob("*.json"))[-a.ultimos :]
    print(json.dumps(summarize(paths), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
