import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from analise_logs import stamp

BASE = Path(__file__).resolve().parent


def summarize(paths, since=None, version="0.3.6"):
    counts, classifications, log_results = Counter(), Counter(), Counter()
    invalid, durations, delays, included = [], [], [], []
    agreement = coherent = total_audits = prose_flags = incomplete = intents = responses = (
        accepted
    ) = confirmations = 0
    source_times = []
    for path in sorted(paths):
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            if not isinstance(doc, dict):
                raise ValueError("Raiz nao e objeto")
        except (OSError, ValueError) as exc:
            invalid.append({"arquivo": str(path), "erro": type(exc).__name__})
            continue
        if doc.get("versao") != version or str(doc.get("modo", "")).startswith("replay"):
            continue
        start, end = stamp(doc.get("inicio_utc")), stamp(doc.get("fim_utc"))
        if since is not None and (start is None or start < since):
            continue
        included.append(str(path))
        if start:
            source_times.append(start)
        incomplete += end is None
        counts[doc.get("status_execucao", "sem_status")] += 1
        diagnosis = doc.get("diagnostico") or {}
        classifications[diagnosis.get("classificacao", "sem_diagnostico")] += 1
        if start and end and end >= start:
            durations.append(round((end - start).total_seconds(), 3))
        metric = doc.get("auditoria_metricas_modelo", {})
        if metric:
            total_audits += 1
            agreement += metric.get("acertos") == metric.get("total")
            coherent += metric.get("coerencia_interna_classificacao") is True
        prose_flags += len(doc.get("auditoria_parcial_prosa", {}).get("alertas", []))
        logs = doc.get("analise_logs_estruturada")
        if logs:
            log_results[logs.get("resultado", "sem_resultado")] += 1
        action = doc.get("investigacao_interfaces") or doc.get("atuacao_controlada") or {}
        evs = action.get("eventos", [])
        intents += sum(ev.get("evento") == "SET_a_enviar" for ev in evs)
        response_rows = [ev for ev in evs if ev.get("evento") == "resposta_SET"]
        responses += len(response_rows)
        accepted += sum(ev.get("resultado") == "aceito" for ev in response_rows)
        confirmed = [
            ev
            for ev in evs
            if ev.get("evento") == "GET_pos_SET" and ev.get("dados", {}).get("admin_status") == 1
        ]
        confirmations += bool(confirmed)
        initial = next(
            (
                stamp(ev.get("utc"))
                for ev in evs
                if ev.get("evento") in ("inventario", "leitura_inicial")
            ),
            None,
        )
        if initial and confirmed and stamp(confirmed[0].get("utc")):
            delay = (stamp(confirmed[0]["utc"]) - initial).total_seconds()
            if delay >= 0:
                delays.append(round(delay, 3))
    return {
        "versao_filtrada": version,
        "desde_utc": since.isoformat() if since else None,
        "registros_analisados": len(included),
        "status_execucao": dict(counts),
        "classificacoes_python": dict(classifications),
        "analises_sem_fim": incomplete,
        "relatorios_com_auditoria_metricas": total_audits,
        "concordancia_todas_metricas": agreement,
        "classificacoes_IA_coerentes_internamente": coherent,
        "sinais_para_revisao_prosa": prose_flags,
        "interpretacao_logs": dict(log_results),
        "intencoes_SET": intents,
        "respostas_SET": responses,
        "SETs_aceitos": accepted,
        "analises_com_GET_admin_1_apos_SET": confirmations,
        "duracoes_analises_s": durations,
        "tempos_observacao_inicial_ate_GET_admin_1_s": delays,
        "primeiro_inicio_utc": min(source_times).isoformat() if source_times else None,
        "ultimo_inicio_utc": max(source_times).isoformat() if source_times else None,
        "arquivos_invalidos": invalid,
        "arquivos": included,
        "limites": [
            "Concordancia assistida com Python nao mede diagnostico independente da IA.",
            "Sinais de revisao da prosa nao sao auditoria factual completa.",
            "Duracao nao mede latencia desde a injecao da falha; tempo de confirmacao inicia na observacao registrada.",
            "Intencao SET, resposta SET e GET posterior sao evidencias distintas.",
            "Sem eventos de atuacao ou injecao identificada, nao conclui ausencia de SET indevido nem recuperacao.",
            "Nao mede cobertura continua entre registros, perdas de logs ou disponibilidade fim a fim.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Resumo dos registros do agente, incluindo interfaces e interpretacao de logs.\n\nNao certifica intervalos sem processo, verdade da prosa ou escolha otima de ferramentas.\n"
    )
    parser.add_argument("--pasta", type=Path, default=BASE / "dados" / "analises")
    parser.add_argument("--desde", help="Inicio com fuso, ex.: 2026-10-13T18:00:00-03:00")
    parser.add_argument("--versao", default="0.3.6")
    args = parser.parse_args()
    since = stamp(args.desde) if args.desde else None
    if args.desde and since is None:
        parser.error("--desde exige data e hora com fuso.")
    summary = summarize(args.pasta.glob("*.json"), since, args.versao)
    output = (
        BASE
        / "dados"
        / "ensaios"
        / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_resumo.json")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {k: v for k, v in summary.items() if k not in ("arquivos", "duracoes_analises_s")},
            ensure_ascii=False,
            indent=2,
        )
    )
    print("Resultado:", output)
