from __future__ import annotations
import argparse
import asyncio
import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from politica_diagnostico import assess, load_context, render_verified

BASE = Path(__file__).resolve().parent


def make_cases():
    base = json.loads((BASE / "casos" / "normal_real.json").read_text(encoding="utf-8"))
    cases = []

    def add(name, expected, change=None, reference=None):
        ev = copy.deepcopy(base["ferramentas"])
        if change:
            change(ev)
        cases.append(
            {
                "nome": name,
                "esperado": expected,
                "evidencias": ev,
                "referencia": reference or base["instante_referencia"],
                "origem": "real" if name == "normal_real" else "variacao_sintetica_do_caso_real",
            }
        )

    def cpu_high(e):
        e[1]["dados"].update(cpu_media_pct=95.0, cpu_indices_pct={str(n): 95 for n in range(1, 5)})

    def ram_high(e):
        e[1]["dados"].update(memoria_pct=92.0, memoria_usada_mib=235.52)

    def expected_link_down(e):
        e[3]["dados"].update(
            oper_status=2, rx_mbps=None, tx_mbps=None, qualidade_taxa="interface_nao_ativa"
        )

    def missing_cpu(e):
        e[1]["dados"].update(cpu_media_pct=None, cpu_indices_pct={}, qualidade="parcial")

    def missing_port(e):
        e[0]["dados"]["interfaces_ultimo_ciclo_max16"] = [
            p for p in e[0]["dados"]["interfaces_ultimo_ciclo_max16"] if p["nome"] != "ether2"
        ]

    def fresh_over_old_history(e):
        for row in e[0]["dados"]["serie"]:
            row["utc"] = (datetime.fromisoformat(row["utc"]) - timedelta(days=1)).isoformat()
        e[0]["dados"].update(idade_s=86409.4, antigo_ou_relogio_invalido=True)
        fresh = copy.deepcopy(e[3])
        fresh.update(id="E4", argumentos={"ifindex": 3})
        fresh["dados"].update(nome="ether2", ifindex=3)
        e.append(fresh)

    def with_marker(e):
        for p in e[0]["dados"]["interfaces_ultimo_ciclo_max16"]:
            if p.get("qualidade_taxa") == "estimado_sem_marcador":
                p["qualidade_taxa"] = "ok"
        e[0]["dados"]["diagnostico_ultimo_ciclo"] = "[]"
        e[3]["dados"]["qualidade_taxa"] = "ok"

    def accumulated_errors(e):
        e[3]["dados"]["contadores_acumulados"]["rx_erros"] = 100

    add("normal_real", "sem_anomalia_evidente")
    add("cpu_95", "suspeita", cpu_high)
    add("ram_92", "suspeita", ram_high)
    add("ether1_sem_link", "suspeita", expected_link_down)
    add("cpu_ausente", "inconclusivo", missing_cpu)
    add("ether2_sem_dados", "inconclusivo", missing_port)
    ref = datetime.fromisoformat(base["instante_referencia"])
    add("todos_dados_antigos", "inconclusivo", reference=(ref + timedelta(minutes=5)).isoformat())
    add(
        "relogio_anterior_as_leituras",
        "inconclusivo",
        reference=(ref - timedelta(minutes=5)).isoformat(),
    )
    add("historico_antigo_consultas_recentes", "sem_anomalia_evidente", fresh_over_old_history)
    add("com_marcador", "sem_anomalia_evidente", with_marker)
    add("contadores_acumulados_nao_sao_taxas", "sem_anomalia_evidente", accumulated_errors)
    add("cpu_fora_da_faixa", "inconclusivo", lambda e: e[1]["dados"].update(cpu_media_pct=150))
    return cases


async def evaluate(args):
    config = load_context()
    config["avaliacao_isolada"] = not getattr(args, "avaliacao_conjunta", False)
    run = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:6]
    folder = BASE / "dados" / "avaliacoes" / run
    folder.mkdir(parents=True)
    blind = args.cego
    metric = "acerto_classificacao_modelo_cego" if blind else "aderencia_classificacao_modelo"
    summary = {
        "versao_avaliador": "0.3.6",
        "modo_avaliacao_metricas": "individual" if config["avaliacao_isolada"] else "conjunta",
        "revisao_avaliador": "modelo_cli_v1",
        "modelo_solicitado": getattr(args, "modelo", "qwen3.5:4b"),
        "modo": "replay_ollama_cego"
        if blind
        else "replay_ollama"
        if args.ollama
        else "offline_python",
        "classificacao_python_fornecida_ao_modelo": bool(args.ollama and not blind),
        "nota": "Replay usa o horario original do caso; nao descreve a RB atual. Variacoes sao sinteticas. "
        "Acerto do perfil nao mede acerto da IA. No modo cego, a classificacao esperada/Python e os alertas nao sao enviados ao modelo. "
        "Casos de desenvolvimento conhecidos, sem avaliacao de generalizacao ou da escolha de ferramentas. A prosa exige revisao separada.",
        "casos": [],
    }
    backend = None
    if args.ollama:
        from agente_ia import Agent, EvidenceTools, LocalOllama

        backend = LocalOllama(getattr(args, "modelo", "qwen3.5:4b"))
        backend.preflight()
        summary["modelo"] = backend.metadata
    for case in make_cases():
        objective = assess(case["evidencias"], config, case["referencia"])
        result = {
            "nome": case["nome"],
            "origem": case["origem"],
            "esperado": case["esperado"],
            "classificacao_python": objective["classificacao"],
            "perfil_ok": objective["classificacao"] == case["esperado"],
            "triagem": render_verified(objective),
        }
        print(
            f"{case['nome']}: Python={objective['classificacao']} | esperado={case['esperado']}",
            flush=True,
        )
        if backend:
            toolset = EvidenceTools(
                SimpleNamespace(host="192.168.88.1"), BASE / "banco_nao_usado.db"
            )
            agent = Agent(backend, toolset, folder / (case["nome"] + ".json"), config)
            agent.record.update(
                ferramentas=case["evidencias"],
                modo="replay_sem_snmp",
                referencia_replay=case["referencia"],
            )
            try:
                proposal = await agent.build_report(
                    "Analise as evidencias no instante de referencia informado. Este e um replay, nao uma leitura do estado atual do equipamento.",
                    case["evidencias"],
                    case["referencia"],
                    include_policy=not blind,
                )
                result["proposta_modelo"] = proposal
                result[metric] = proposal["classificacao"] == case["esperado"]
                result["auditoria_metricas_modelo"] = agent.record["auditoria_metricas_modelo"]
                agent.record["proposta_original_modelo"] = proposal
                audit = result["auditoria_metricas_modelo"]
                print(
                    f"  Modelo={proposal['classificacao']} | metricas={audit['acertos']}/{audit['total']} "
                    f"| classificacao coerente com seus estados={audit['coerencia_interna_classificacao']}",
                    flush=True,
                )
                for check in audit["metricas"]:
                    if not check["coincide"]:
                        print(
                            f"    {check['metrica']}: modelo={check['modelo']} | perfil={check['perfil_python']}",
                            flush=True,
                        )
            except Exception as exc:
                result["erro_modelo"] = f"{type(exc).__name__}: {exc}"
                result[metric] = False
            agent.record["resultado_replay"] = result
            agent.save()
        summary["casos"].append(result)
        (folder / "resumo.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(
        f"\nPerfil Python: {sum(c['perfil_ok'] for c in summary['casos'])}/{len(summary['casos'])} casos com resultado esperado."
    )
    if backend:
        title = (
            "Acerto da classificacao no replay cego"
            if blind
            else "Aderencia da classificacao do modelo"
        )
        print(
            f"{title}: {sum(c[metric] for c in summary['casos'])}/{len(summary['casos'])}. A prosa exige revisao separada."
        )
        audits = [
            c["auditoria_metricas_modelo"]
            for c in summary["casos"]
            if "auditoria_metricas_modelo" in c
        ]
        expected_total = len(summary["casos"]) * (2 + len(config["interfaces_com_link_esperado"]))
        summary["auditoria_agregada"] = {
            "metricas_corretas": sum(a["acertos"] for a in audits),
            "metricas_previstas": expected_total,
            "casos_com_relatorio_valido": len(audits),
            "casos_coerentes_internamente": sum(
                a["coerencia_interna_classificacao"] for a in audits
            ),
        }
        print(
            f"Estados por metrica: {summary['auditoria_agregada']['metricas_corretas']}/{expected_total}. "
            "Relatorios invalidos nao contam como acerto."
        )
        (folder / "resumo.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print("Resultado: " + str(folder / "resumo.json"))
    return 0 if all(c["perfil_ok"] for c in summary["casos"]) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reproduz evidencias gravadas. Nao acessa a RB, nao treina o modelo."
    )
    parser.add_argument(
        "--ollama",
        action="store_true",
        help="Tambem consulta o modelo local em cada caso; nao consulta SNMP.",
    )
    parser.add_argument(
        "--modelo",
        default="qwen3.5:4b",
        help="Modelo local instalado para comparar com as mesmas entradas.",
    )
    parser.add_argument(
        "--cego",
        action="store_true",
        help="Com --ollama: omite o veredito Python e os alertas do contexto enviado ao modelo.",
    )
    parser.add_argument(
        "--avaliacao-conjunta",
        action="store_true",
        help="Compara com a geracao conjunta anterior; padrao: metricas individuais.",
    )
    try:
        args = parser.parse_args()
        if args.cego and not args.ollama:
            parser.error("Use --cego junto com --ollama.")
        raise SystemExit(asyncio.run(evaluate(args)))
    except KeyboardInterrupt:
        raise SystemExit("Avaliacao interrompida; resultados ja gravados foram preservados.")
