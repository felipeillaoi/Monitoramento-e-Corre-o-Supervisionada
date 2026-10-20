import argparse
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from agente_ia import (
    Agent,
    AgentError,
    ContextBudgetError,
    EvidenceTools,
    LocalOllama,
    Client,
    SYSTEM,
    LOG_SYSTEM,
    TOOLS,
    LOG_TOOL,
    MAX_CALLS,
    planning_evidence,
    read_history,
    dumps,
    now,
)
from politica_diagnostico import load_context, assess, render_verified, DEFAULT_CONTEXT
from contexto_supervisionado import temporal_summary, make_packet
from investigacao_interfaces import Client as InterfaceClient, run_interfaces, validate_plan
from revisor_gpt import GPTReviewer, DEFAULT_MODEL
from supervisao import supervise
from plano_operacional import bind_plan, bind_detected_plan
from monitoramento_continuo import (
    load_profile,
    DEFAULT_PROFILE,
    IncidentTracker,
    MonitorLock,
    write_hold_status,
)
from investigacao_interfaces import PORTS
from analise_logs import declared_offset
from observacao_wan import WANObserver, TOOL as WAN_TOOL
from diagnostico_ampliado import build_findings, show_findings

BASE = Path(__file__).resolve().parent


class TemporalTools(EvidenceTools):
    async def execute(self, name, args):
        if name == "consultar_estado_wan":
            if args or not getattr(self, "wan_observer", None):
                return {
                    "tem_dados": False,
                    "utc": now(),
                    "erro": "Observacao WAN desativada ou credenciais ausentes.",
                }, []

            return self.clean(await self.wan_observer.observe()), []
        if name == "ler_historico" and args == {}:
            try:
                data = read_history(self.database, self.client.host, limit=120)
                data["resumo_temporal"] = temporal_summary(data.get("serie", []), now())
                return self.clean(data), []
            except Exception as exc:
                return {"tem_dados": False, "erro": type(exc).__name__}, []
        return await super().execute(name, args)


async def gather(agent, question):
    agent.record["pergunta"] = question
    evidence = [await agent.collect("ler_historico", {}, "programa")]
    view = planning_evidence(evidence[0])
    agent.record["visoes_planejamento_modelo"] = [view]
    messages = [
        {"role": "system", "content": SYSTEM + LOG_SYSTEM},
        {"role": "user", "content": question},
        {"role": "user", "content": "Evidencia inicial: " + dumps(view)},
    ]
    calls = 0
    for _ in range(MAX_CALLS):
        if calls >= MAX_CALLS:
            break
        try:
            response = await agent.chat(
                messages,
                tools=TOOLS
                + ([LOG_TOOL] if agent.tools.logs_enabled else [])
                + ([WAN_TOOL] if getattr(agent.tools, "wan_observer", None) else []),
            )
        except ContextBudgetError as exc:
            agent.record["planejamento_interrompido_por_contexto"] = str(exc)
            break
        requested = response.get("tool_calls", [])
        if not requested:
            break
        if not isinstance(requested, list):
            raise AgentError("Lista de ferramentas malformada.")
        remaining = MAX_CALLS - calls
        if len(requested) > remaining:
            agent.record.setdefault("limites_planejamento", []).append(
                {
                    "utc": now(),
                    "solicitadas": len(requested),
                    "orcamento_restante": remaining,
                    "selecionadas_para_execucao": remaining,
                    "omitidas": len(requested) - remaining,
                    "criterio": "Primeiras chamadas na ordem proposta pelo modelo; nenhuma chamada excedente executada.",
                }
            )
            agent.save()
            print(
                f"Qwen solicitou {len(requested)} consultas; restam {remaining}. "
                f"Executando somente as {remaining} primeiras; demais registradas como omitidas.",
                flush=True,
            )
            requested = requested[:remaining]
        normalized = []
        for item in requested:
            fn = item.get("function", {}) if isinstance(item, dict) else {}
            if (
                not isinstance(fn, dict)
                or not isinstance(fn.get("name"), str)
                or not isinstance(fn.get("arguments", {}), dict)
            ):
                raise AgentError("Chamada de ferramenta malformada.")
            normalized.append(
                {
                    "type": "function",
                    "function": {"name": fn["name"], "arguments": fn.get("arguments", {})},
                }
            )
        messages.append({"role": "assistant", "content": "", "tool_calls": normalized})
        for item in normalized:
            fn = item["function"]
            ev = await agent.collect(fn["name"], fn["arguments"], "IA")
            evidence.append(ev)
            view = planning_evidence(ev)
            agent.record["visoes_planejamento_modelo"].append(view)
            messages.append({"role": "tool", "tool_name": fn["name"], "content": dumps(view)})
            calls += 1
    agent.record["limite_ferramentas_atingido"] = calls >= MAX_CALLS
    agent.record["chamadas_ferramentas_IA_executadas"] = calls

    if not any(e["ferramenta"] == "consultar_cpu_memoria" for e in evidence):
        evidence.append(await agent.collect("consultar_cpu_memoria", {}, "programa_cobertura"))
    await agent.complete_coverage(evidence)
    if agent.tools.logs_enabled and not any(
        e["ferramenta"] == "consultar_logs_arquivados" for e in evidence
    ):
        evidence.append(
            await agent.collect(
                "consultar_logs_arquivados", {"interface": "geral"}, "programa_cobertura_logs"
            )
        )
    objective = assess(evidence, agent.context, now())
    agent.record["avaliacao_objetiva_final"] = objective
    agent.record["diagnostico"] = render_verified(objective)
    print("\nTRIAGEM CPU/RAM/LINKS (escopo restrito):", objective["classificacao"])
    print(agent.record["diagnostico"]["resumo"])
    if agent.record.get("diagnostico_ampliado", {}).get("problemas"):
        print(
            "Ha achados adicionais na avaliacao ampliada; esta triagem restrita nao cobre DHCP/DNS/rotas/disco."
        )
    agent.save()
    return evidence


def extract_investigation(result):
    states = {}
    details = {}
    for event in result.get("eventos", []):
        if event["evento"] == "inventario":
            states = dict(event["dados"])
        if event["evento"] == "investigacao_SNMP":
            details[event["id"]] = event["dados"]
            states[event["interface"]] = event["dados"]["estado_final"]
    candidates = []
    if result.get("plano_IA"):
        _, candidates = validate_plan(dumps(result["plano_IA"]), states, details)

    if result.get("resultado") not in (
        "simulacao_habilitacao_proposta_sem_SET",
        "sem_correcao_administrativa_indicada",
    ):
        candidates = []
    return candidates, states, details


async def cycle(args, backend, reviewer, auth, privacy, write_credentials, session, tracker=None):
    path = (
        BASE
        / "dados"
        / "analises_supervisionadas"
        / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "_"
            + uuid.uuid4().hex[:8]
            + ".json"
        )
    )
    main = Client(args.host, args.usuario, auth, privacy)
    reader = InterfaceClient(args.usuario, auth, privacy)
    writer = None
    wan_observer = None
    wan_enabled = getattr(args, "observacao_wan_habilitada", False)
    wan_ev = None
    report = None
    secrets = (
        (auth, privacy) + tuple(write_credentials or ()) + ((reviewer.key,) if reviewer else ())
    )
    tools = TemporalTools(main, args.banco, secrets, logs_enabled=not args.sem_logs)
    agent = Agent(backend, tools, path, args.context)
    agent.record.update(
        versao="0.6.0",
        arquitetura="qwen_gpt_humano_snmp",
        pergunta=args.pergunta,
        status_execucao="em_andamento",
        modelo_revisor=reviewer.model if reviewer else None,
    )
    agent.save()
    outcome = {"resultado": "erro_analise"}
    due = []
    try:
        await main.connect()
        await reader.connect()
        if wan_enabled and write_credentials:
            wan_observer = WANObserver("tcc-escrita", *write_credentials)
            await wan_observer.connect()
            tools.wan_observer = wan_observer
        if tracker is not None:
            metric_ev = await agent.collect("consultar_cpu_memoria", {}, "programa_monitoramento")
            try:
                inventory = await reader.inventory()
            except Exception as exc:
                inventory = {}
                agent.record["falha_inventario"] = type(exc).__name__
            if wan_enabled:
                wan_ev = await agent.collect("consultar_estado_wan", {}, "programa_observacao_wan")
            report = build_findings(
                metric_ev["dados"],
                inventory,
                args.context,
                args.profile,
                now(),
                metric_ev["id"],
                wan_ev["dados"] if wan_ev else None,
                wan_ev["id"] if wan_ev else None,
            )
            agent.record["diagnostico_ampliado"] = report
            agent.record["inventario_monitoramento"] = {
                "id": "I0",
                "utc": now(),
                "dados": inventory,
            }
            show_findings(report)
            signals = report["sinais"]
            due = tracker.observe(signals)
            agent.record["monitoramento"] = {
                "sinais": signals,
                "eventos": tracker.events,
                "pendencias_para_analise": due,
                "perfil": args.profile,
                "incidentes": tracker.entries.copy(),
            }
            for item in tracker.remind():
                print(
                    "PENDENCIA:",
                    item["chave"],
                    "|",
                    item["estado"],
                    "| resultado anterior:",
                    item["resultado"],
                )
            if not signals and not args.analisar_sempre and not args.restaurar_interface:
                print("MONITORAMENTO: sem desvio nos criterios atuais; nenhuma chamada Qwen/GPT.")
                agent.record["status_execucao"] = "monitoramento_sem_desvio"
                outcome = {"resultado": "monitoramento_sem_desvio"}
                return outcome
            if not due and not args.analisar_sempre and not args.restaurar_interface:
                waiting = tracker.waiting()
                agent.record["monitoramento"]["adiamentos"] = waiting
                print("MONITORAMENTO: pendencias ja avaliadas; sem nova proposta neste ciclo.")
                for item in waiting:
                    reason = (
                        f"nova analise elegivel em {item['restante_s']}s; sera feita em um proximo ciclo"
                        if item["restante_s"] is not None
                        else "aguardando mudanca de estado ou reavaliacao manual"
                    )
                    print(
                        f"  {item['chave']} | resultado anterior: {item['resultado_anterior']} | {reason}"
                    )
                agent.record["status_execucao"] = "monitoramento_sem_nova_analise"
                outcome = {"resultado": "monitoramento_sem_nova_analise"}
                return outcome
            if (
                wan_enabled
                and signals
                and all(
                    key in ("dhcp:wan", "ipv4:wan", "rota:main", "dns:router", "disco")
                    and value == "dados_indisponiveis"
                    for key, value in signals.items()
                )
                and not args.analisar_sempre
            ):
                print(
                    "OBSERVACAO WAN PENDENTE: confira instalacao/permissoes. Achado registrado; sem chamadas aos modelos neste ciclo."
                )
                agent.record["status_execucao"] = "observacao_wan_indisponivel"
                outcome = {"resultado": "observacao_wan_indisponivel"}
                return outcome
            if not inventory:
                print("MONITORAMENTO: inventario SNMP indisponivel; nenhuma atuacao autorizada.")
                agent.record["status_execucao"] = "monitoramento_inconclusivo"
                outcome = {"resultado": "erro_analise"}
                return outcome
        await gather(agent, args.pergunta)

        preparation = await run_interfaces(
            agent,
            reader,
            None,
            False,
            BASE / "dados" / "atuacao",
            {"tentativas": 0},
            **({"complete_pending": True} if tracker is not None else {}),
        )
        if preparation.get("resultado") not in (
            "simulacao_habilitacao_proposta_sem_SET",
            "sem_correcao_administrativa_indicada",
        ):
            raise AgentError(
                "Investigacao de interfaces incompleta ou plano Qwen invalido; nenhuma correcao sera oferecida."
            )
        candidates, states, details = extract_investigation(preparation)

        if tracker is not None and not args.sem_logs:
            focus = next(
                (name for name in PORTS if "interface:" + name in due),
                "ether1"
                if any(k in due for k in ("dhcp:wan", "ipv4:wan", "rota:main", "dns:router"))
                else None,
            )
            if focus and not any(
                e["ferramenta"] == "consultar_logs_arquivados"
                and e["argumentos"].get("interface") == focus
                for e in agent.record["ferramentas"]
            ):
                await agent.collect(
                    "consultar_logs_arquivados",
                    {"interface": focus},
                    "programa_cobertura_incidente",
                )
        packet = make_packet(agent, candidates, states, details, now())
        target = getattr(args, "restaurar_interface", None)
        if tracker is not None and target is None:
            allowed = [name for name in PORTS if "interface:" + name in due]
            packet = bind_detected_plan(packet, preparation, states, details, args.profile, allowed)
        else:
            packet = bind_plan(packet, preparation, states, details, target)
        if tracker is not None:
            latest_cpu = next(
                e
                for e in reversed(agent.record["ferramentas"])
                if e["ferramenta"] == "consultar_cpu_memoria"
            )
            latest_wan = next(
                (
                    e
                    for e in reversed(agent.record["ferramentas"])
                    if e["ferramenta"] == "consultar_estado_wan"
                ),
                None,
            )
            report = build_findings(
                latest_cpu["dados"],
                states,
                args.context,
                args.profile,
                now(),
                latest_cpu["id"],
                latest_wan["dados"] if latest_wan else None,
                latest_wan["id"] if latest_wan else None,
            )
            iface_refs = {r["interface"]: r["evidencia"] for r in packet["interfaces"]}
            for finding in report["problemas"]:
                if finding["chave_incidente"].startswith("interface:"):
                    finding["evidencias"] = [
                        iface_refs[finding["chave_incidente"].split(":", 1)[1]]
                    ]
            packet["avaliacao_ampliada"] = report["classificacao"]
            packet["problemas_observados"] = [
                {
                    k: f[k]
                    for k in (
                        "id",
                        "codigo",
                        "problema",
                        "qualidade",
                        "evidencias",
                        "correcao_disponivel",
                        "proxima_verificacao",
                    )
                }
                for f in report["problemas"]
            ]
            packet["limites"] += (
                " Problema observado nao implica correcao disponivel. Nenhuma correcao DHCP, rota, DNS ou disco esta implementada."
            )
            agent.record["diagnostico_ampliado"] = report
        agent.record["objetivo_operador"] = packet["objetivo_operador"]
        agent.record["plano_operacional_qwen"] = packet.get("plano_operacional_qwen")
        agent.save()
        if args.executar_correcoes and packet.get("acoes_elegiveis_python"):
            hold, retry_at = write_hold_status(BASE / "dados" / "atuacao", session)
            if hold:
                print("OFERTA DE CORRECAO ADIADA:", hold, "| monitoramento continua; nenhum SET.")
                agent.record["status_execucao"] = hold
                outcome = {"resultado": hold}
                if retry_at is not None:
                    outcome["reavaliar_apos_epoch"] = retry_at
                    print(
                        "Reanalise agendada para o fim do intervalo global entre SETs; dados e proposta serao obtidos novamente."
                    )
                return outcome
        if args.executar_correcoes and write_credentials and packet.get("acoes_elegiveis_python"):
            writer = InterfaceClient("tcc-escrita", *write_credentials)
            await writer.connect()
        result = await supervise(
            agent,
            reader,
            writer,
            packet,
            states,
            reviewer,
            args.executar_correcoes,
            args.contingencia_local,
            BASE / "dados" / "atuacao",
            session,
            feedback_enabled=not getattr(args, "sem_reformulacao", False),
        )
        outcome = result
        print("\nRESULTADO SUPERVISIONADO:", result["resultado"])
        if result.get("estado_final"):
            final = result["estado_final"]
            print(
                f"GET final: {final['nome']} admin={final['admin_status']} oper={final['oper_status']}"
            )
        agent.record["status_execucao"] = (
            "concluida" if result.get("revisao_concluida") else "concluida_sem_aprovacao_gpt"
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        agent.record["status_execucao"] = "interrompida"
        raise
    except Exception as exc:
        detail = (
            agent.tools.clean(str(exc))[:500]
            if isinstance(exc, (AgentError, ValueError))
            else "Falha na etapa; tipo registrado."
        )
        agent.record.update(
            status_execucao="inconclusiva", erro={"tipo": type(exc).__name__, "detalhe": detail}
        )
        print("Analise interrompida:", type(exc).__name__, "|", detail)
    finally:
        if tracker is not None:
            deferred = (
                set(packet.get("acoes_adiadas_para_outro_ciclo", []))
                if "packet" in locals()
                else set()
            )
            if due:
                tracker.complete(
                    [key for key in due if key.removeprefix("interface:") not in deferred],
                    outcome["resultado"],
                    retry_at=outcome.get("reavaliar_apos_epoch"),
                )
            if outcome["resultado"] in ("habilitacao_confirmada", "habilitada_sem_confirmacao_SET"):
                final = outcome.get("estado_final", {})
                acted = outcome.get("acao_apresentada", {}).get("interface")
                if final.get("nome") == acted:
                    event = tracker.reconcile_post_set(final, args.context, now())
                    if event:
                        agent.record["monitoramento"]["reconciliacao_pos_SET"] = event
                        print("MONITORAMENTO POS-SET:", event["chave"], "|", event["evento"])
        agent.record["fim_utc"] = now()
        agent.save()
        main.close()
        reader.close()
        if writer:
            writer.close()
        if wan_observer:
            wan_observer.close()
        print("Registro completo:", path)
    return outcome


async def run(args, backend, reviewer, auth, privacy, write_credentials):
    session = {"tentativas": 0, "limite": args.max_set_sessao}

    mode = "execucao" if args.executar_correcoes else "local" if args.somente_local else "simulacao"
    tracker = IncidentTracker(
        BASE
        / "dados"
        / "monitoramento_continuo"
        / ("incidentes_" + args.host + "_" + mode + ".json"),
        args.profile,
        reset=args.reavaliar_pendencias,
    )
    i = 0
    while args.ciclos == 0 or i < args.ciclos:
        i += 1
        print(f"\n=== Ciclo supervisionado {i}/{args.ciclos or 'continuo'} ===")
        await cycle(args, backend, reviewer, auth, privacy, write_credentials, session, tracker)
        if args.ciclos == 0 or i < args.ciclos:
            print(f"Proxima leitura em {args.intervalo}s. Ctrl+C encerra.")
            await asyncio.sleep(args.intervalo)


def parser():
    p = argparse.ArgumentParser(
        description="v0.6.0: Qwen local + revisao GPT + confirmacao humana + executor SNMP.\nEntrada nova; agente_ia.py e seus avaliadores permanecem como base v0.3.6.\n"
    )
    p.add_argument("--modelo", default="qwen3.5:4b")
    p.add_argument("--modelo-gpt", default=DEFAULT_MODEL)
    p.add_argument("--host", default="192.168.88.1", choices=["192.168.88.1"])
    p.add_argument("--usuario", default="tcc-monitor")
    p.add_argument("--banco", type=Path, default=BASE / "dados" / "monitoramento.db")
    p.add_argument("--contexto", type=Path, default=DEFAULT_CONTEXT)
    p.add_argument("--fuso-logs", default="-03:00")
    p.add_argument("--sem-logs", action="store_true")
    p.add_argument(
        "--sem-observacao-wan",
        action="store_true",
        help="Desativa observacao ampliada por script; ainda monitora CPU/RAM e portas.",
    )
    p.add_argument(
        "--restaurar-interface",
        choices=["ether1", "ether5"],
        help="Objetivo explicito de restaurar admin_status=1 na porta autorizada; a redacao preserva a acao do plano Qwen.",
    )
    p.add_argument(
        "--sem-reformulacao",
        action="store_true",
        help="Comparacao: encerra na primeira rejeicao GPT, sem retorno ao Qwen.",
    )
    p.add_argument(
        "--somente-local",
        action="store_true",
        help="Simulacao sem enviar dados a API; nao permite SET.",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--executar-correcoes",
        dest="executar_correcoes",
        action="store_true",
        help="Modo supervisionado padrao: cada SET exige revisao e confirmacao humana.",
    )
    mode.add_argument(
        "--simular",
        dest="executar_correcoes",
        action="store_false",
        help="Analisa e revisa propostas, mas nunca envia SET.",
    )
    p.set_defaults(executar_correcoes=True)
    p.add_argument(
        "--perfil",
        type=Path,
        default=DEFAULT_PROFILE,
        help="Estado desejado do laboratorio; nao amplia catalogo nem identidade.",
    )
    p.add_argument(
        "--reavaliar-pendencias",
        action="store_true",
        help="Reabre analises suprimidas de incidentes atuais; nao apaga auditoria nem cooldown de escrita.",
    )
    p.add_argument(
        "--analisar-sempre",
        action="store_true",
        help="Solicita Qwen/GPT a cada ciclo, inclusive sem desvio; pode gerar cobranca repetida.",
    )
    p.add_argument(
        "--max-set-sessao",
        type=int,
        default=10,
        help="Limite de tentativas SET na sessao (padrao 10); no maximo uma por ciclo/episodio e intervalo global de 300s.",
    )
    p.add_argument(
        "--contingencia-local",
        action="store_true",
        help="Somente em falha temporaria real da API: oferece aprovacao LOCAL etherN; nao contorna rejeicao/erro de credencial.",
    )
    p.add_argument(
        "--pergunta",
        default="Analise CPU, memoria, interfaces e logs. Compare o historico temporal, explique limitacoes e proponha uma acao somente se houver evidencias suficientes.",
    )
    p.add_argument(
        "--ciclos",
        type=int,
        default=0,
        help="0: continuo ate Ctrl+C; valor positivo: quantidade de leituras.",
    )
    p.add_argument("--intervalo", type=int, default=60)
    p.add_argument("--timeout-gpt", type=int, default=20)
    return p


def main():
    p = parser()
    args = p.parse_args()
    if args.somente_local:
        args.executar_correcoes = False
    if args.contingencia_local and (args.somente_local or not args.executar_correcoes):
        p.error("--contingencia-local exige --executar-correcoes e tentativa de revisao GPT.")
    if not 0 <= args.ciclos <= 1000000 or not 10 <= args.intervalo <= 3600:
        p.error("Use 0..1000000 ciclos (0 continuo) e intervalo 10..3600s.")
    if not 1 <= args.max_set_sessao <= 100:
        p.error("Use --max-set-sessao entre 1 e 100.")
    if not 5 <= args.timeout_gpt <= 30:
        p.error("Timeout GPT entre 5 e 30s.")
    if not 1 <= len(args.pergunta) <= 800:
        p.error("Pergunta entre 1 e 800 caracteres.")
    if args.executar_correcoes and not sys.stdin.isatty():
        p.error("Execucao exige terminal interativo para aprovacao.")
    declared_offset(args.fuso_logs)
    args.context = load_context(args.contexto)
    args.context["fuso_logs"] = args.fuso_logs
    args.profile = load_profile(args.perfil)
    args.observacao_wan_habilitada = not args.sem_observacao_wan
    args.profile["observacao_wan_habilitada"] = args.observacao_wan_habilitada
    print("Agente supervisionado v0.6.0 | laboratorio RB750Gr3 | SNMPv3")
    print(
        "SIMULACAO: nenhum SET"
        if not args.executar_correcoes
        else f"EXECUCAO SUPERVISIONADA: ate {args.max_set_sessao} tentativas SET nesta sessao; uma por ciclo e confirmacao por proposta."
    )
    print(
        "Objetivo:",
        "restaurar administrativamente " + args.restaurar_interface
        if args.restaurar_interface
        else "detectar desvios e manter estado desejado de " + str(args.perfil),
    )
    if not args.somente_local:
        print(
            "Revisao remota:",
            args.modelo_gpt,
            "| Envia pergunta, metricas, resumo temporal, trechos de logs e proposta com minimizacao de dados.",
        )
        print(
            "A API tem cobranca propria. Chave fica somente em memoria; Enter sem chave deixa a revisao pendente."
        )
        key = os.environ.get("OPENAI_API_KEY") or getpass("Chave da API OpenAI (entrada oculta): ")
        reviewer = GPTReviewer(key.strip(), args.modelo_gpt, args.timeout_gpt)
    else:
        reviewer = None
        print("Modo local: sem envio a API e sem SET.")
    backend = LocalOllama(args.modelo)
    backend.preflight()
    auth = getpass("Senha de autenticacao SNMPv3 de leitura: ")
    privacy = getpass("Senha de criptografia SNMPv3 de leitura: ")
    if min(len(auth), len(privacy)) < 8:
        p.error("Senhas SNMP devem ter pelo menos 8 caracteres.")
    write = None
    if args.executar_correcoes or args.observacao_wan_habilitada:
        if not args.executar_correcoes:
            print(
                "Observacao WAN: tcc-escrita e exigida para executar o script de LEITURA por GET; simulacao continua sem alteracao de rede."
            )
        write = (
            getpass("Senha de autenticacao de tcc-escrita: "),
            getpass("Senha de criptografia de tcc-escrita: "),
        )
        if min(map(len, write)) < 8:
            p.error("Senhas de escrita devem ter pelo menos 8 caracteres.")
    with MonitorLock(BASE / "dados" / "monitoramento_continuo" / "agente.lock"):
        asyncio.run(run(args, backend, reviewer, auth, privacy, write))


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrompido pelo operador. Consulte eventual registro parcial.")
    except (AgentError, OSError, ValueError) as exc:
        raise SystemExit("Falha: " + str(exc))
