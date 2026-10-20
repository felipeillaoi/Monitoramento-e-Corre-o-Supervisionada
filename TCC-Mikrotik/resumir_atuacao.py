import argparse
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent


def summarize(items):
    results, initial_states = Counter(), Counter()
    intentions = responses = accepted = confirmed = 0
    mismatches = unfinished = 0
    delays = []
    rows = []
    for name, doc in items:
        events = doc["eventos"]
        starts = [e for e in events if e.get("evento") == "leitura_inicial"]
        ends = [e for e in events if e.get("evento") == "fim"]
        result = ends[-1].get("resultado", "sem_resultado") if ends else "sem_fim_registrado"
        results[result] += 1
        if not ends:
            unfinished += 1
        start = starts[0] if starts else None
        if start:
            initial_states[str(start["dados"].get("admin_status"))] += 1
        sends = [e for e in events if e.get("evento") == "SET_a_enviar"]
        replies = [e for e in events if e.get("evento") == "resposta_SET"]
        good_replies = [e for e in replies if e.get("resultado") == "aceito"]
        posts = [e for e in events if e.get("evento") == "GET_pos_SET"]
        intentions += len(sends)
        responses += len(replies)
        accepted += len(good_replies)

        verified = False
        if start and sends and good_replies and result == "habilitacao_confirmada":
            before = start["dados"]
            for post in posts:
                after = post["dados"]
                same = all(
                    before.get(k) is not None and before.get(k) == after.get(k)
                    for k in ("ifindex", "nome", "mac")
                )
                if before.get("admin_status") == 2 and after.get("admin_status") == 1 and same:
                    verified = True
                    try:
                        delta = (
                            datetime.fromisoformat(post["utc"])
                            - datetime.fromisoformat(start["utc"])
                        ).total_seconds()
                        if delta >= 0:
                            delays.append(round(delta, 3))
                    except (ValueError, TypeError):
                        pass
                    break
        if verified:
            confirmed += 1
        for e in events:
            if e.get("evento") == "validacao_estados_IA" and e.get("confere") is False:
                mismatches += 1
        rows.append(
            {
                "arquivo": name,
                "inicio_utc": doc.get("inicio_utc"),
                "modo": "execucao" if doc.get("habilitar_solicitado") else "simulacao",
                "resultado": result,
                "intencoes_SET": len(sends),
                "habilitacao_confirmada_nas_evidencias": verified,
            }
        )
    return {
        "escopo": "etapa_de_atuacao_ether5",
        "registros_analisados": len(items),
        "resultados": dict(results),
        "estados_administrativos_iniciais": dict(initial_states),
        "registros_sem_fim": unfinished,
        "intencoes_SET": intentions,
        "respostas_SET": responses,
        "SETs_aceitos": accepted,
        "habilitacoes_confirmadas_nas_evidencias": confirmed,
        "divergencias_estados_IA_registradas": mismatches,
        "tempos_da_primeira_leitura_ate_confirmacao_s": delays,
        "arquivos": rows,
        "limites": [
            "Concordancia com regras e estrutura nao comprova qualidade geral do modelo.",
            "Este resumo nao audita o diagnostico geral, o coletor ou os periodos em que o processo nao esteve executando.",
            "Tempo medido inicia na leitura da falha; nao mede desde sua ocorrencia real.",
            "Intencao registrada nao comprova entrega de pacote. Resposta SET e GET sao evidencias distintas.",
            "Sem injecao de falhas, este ensaio observa estabilidade e propostas indevidas no periodo.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Resume registros de atuacao sem consultar rede ou executar correcoes."
    )
    parser.add_argument("--ultimos", type=int, default=60)
    parser.add_argument("--versao", default="0.2.6")
    parser.add_argument("--pasta", type=Path, default=BASE / "dados" / "atuacao" / "registros")
    args = parser.parse_args()
    if not 1 <= args.ultimos <= 100000:
        parser.error("--ultimos deve estar entre 1 e 100000.")
    items, invalid = [], []
    for path in sorted(args.pasta.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(doc, dict):
                raise ValueError("Objeto JSON esperado")
            if doc.get("versao") != args.versao:
                continue
            if not isinstance(doc.get("eventos"), list):
                raise ValueError("Eventos ausentes")
            if any(not isinstance(e, dict) for e in doc["eventos"]):
                raise ValueError("Evento malformado")
            for e in doc["eventos"]:
                if e.get("evento") in ("leitura_inicial", "GET_pos_SET") and not isinstance(
                    e.get("dados"), dict
                ):
                    raise ValueError("Leitura malformada")
            items.append((path.name, doc))
        except (ValueError, OSError) as exc:
            invalid.append({"arquivo": path.name, "erro": type(exc).__name__})
    selected = items[-args.ultimos :]
    summary = summarize(selected)
    summary.update(
        {
            "versao_filtrada": args.versao,
            "quantidade_solicitada": args.ultimos,
            "quantidade_disponivel": len(items),
            "arquivos_invalidos_encontrados": invalid,
        }
    )
    folder = BASE / "dados" / "avaliacoes_atuacao"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + uuid.uuid4().hex[:8]
        + "_resumo.json"
    )
    target.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Registros v{args.versao}: {len(selected)}/{args.ultimos} solicitados")
    for status, count in summary["resultados"].items():
        print(f"  {status}: {count}")
    print("Intencoes SET:", summary["intencoes_SET"])
    print("SETs aceitos:", summary["SETs_aceitos"])
    print("Habilitacoes confirmadas:", summary["habilitacoes_confirmadas_nas_evidencias"])
    print("Registros sem fim:", summary["registros_sem_fim"])
    print("Arquivos invalidos encontrados:", len(invalid))
    if len(selected) < args.ultimos:
        print("ATENCAO: quantidade solicitada ainda nao foi atingida.")
    print("Resultado:", target)


if __name__ == "__main__":
    main()
