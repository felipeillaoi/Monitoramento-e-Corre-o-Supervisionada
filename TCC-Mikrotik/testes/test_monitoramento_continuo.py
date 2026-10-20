import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agente_supervisionado as module
from monitoramento_continuo import (
    load_profile,
    current_signals,
    IncidentTracker,
    write_hold,
    MonitorLock,
)
from plano_operacional import bind_detected_plan
from investigacao_interfaces import PORTS, expected_action
from politica_diagnostico import load_context
from snmp_ether5 import utcnow
from test_investigacao_interfaces import Device, states
import test_supervisionado as support
from test_supervisionado import opinion
from supervisao import supervise as real_supervise, proposal_schema


def fresh_states():
    result = states()
    for state in result.values():
        state["utc"] = utcnow()
    return result


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile()
        self.context = load_context()
        self.metrics = {"tem_dados": True, "cpu_media_pct": 1, "memoria_pct": 24}

    def signals(self, metrics=None, data=None):
        return current_signals(
            metrics or self.metrics,
            data if data is not None else fresh_states(),
            self.context,
            self.profile,
            utcnow(),
        )

    def test_normal_including_ether5_no_cable(self):
        self.assertEqual(self.signals(), {})

    def test_each_disabled_port_detected_including_protected_management(self):
        for name in PORTS:
            data = fresh_states()
            data[name].update(admin_status=2, oper_status=2)
            self.assertIn("interface:" + name, self.signals(data=data))

    def test_wan_link_down_no_assumption_of_cause(self):
        data = fresh_states()
        data["ether1"]["oper_status"] = 2
        self.assertEqual(self.signals(data=data), {"interface:ether1": "admin=1;oper=2"})

    def test_cpu_and_ram_high(self):
        self.assertEqual(
            self.signals(dict(self.metrics, cpu_media_pct=95, memoria_pct=92)),
            {"cpu": "acima_do_limiar", "ram": "acima_do_limiar"},
        )

    def test_absent_invalid_future_or_old_data_are_not_healthy(self):
        for value in (None, True, -1, 150, float("nan")):
            self.assertEqual(
                self.signals(dict(self.metrics, cpu_media_pct=value))["cpu"], "dados_indisponiveis"
            )
        data = fresh_states()
        data["ether1"]["utc"] = "2000-01-01T00:00:00+00:00"
        self.assertEqual(self.signals(data=data)["interface:ether1"], "dados_indisponiveis")

    def test_profile_can_mark_bench_intentionally_disabled(self):
        self.profile["interfaces"]["ether5"].update(admin_desejado=2, propor_habilitacao=False)
        data = fresh_states()
        data["ether5"]["admin_status"] = 2
        self.assertEqual(self.signals(data=data), {})

    def test_profile_cannot_authorize_protected_or_unknown_port(self):
        for name in ("ether2", "ether3"):
            with tempfile.TemporaryDirectory() as t:
                p = copy.deepcopy(self.profile)
                p["interfaces"][name] = {
                    "admin_desejado": 1,
                    "link_exigido": True,
                    "propor_habilitacao": True,
                }
                path = Path(t) / "p.json"
                path.write_text(json.dumps(p))
                with self.assertRaises(ValueError):
                    load_profile(path)


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.json"
        self.profile = load_profile()
        self.tick = [1000]
        self.tracker = IncidentTracker(self.path, self.profile, clock=lambda: self.tick[0])

    def tearDown(self):
        self.temp.cleanup()

    def test_refusal_suppresses_repeat_even_after_restart_and_time(self):
        signals = {"interface:ether5": "admin=2;oper=opcional"}
        self.assertEqual(self.tracker.observe(signals), ["interface:ether5"])
        self.tracker.complete(list(signals), "cancelado_operador")
        self.tick[0] += 10000
        self.assertEqual(self.tracker.observe(signals), [])
        second = IncidentTracker(self.path, self.profile, clock=lambda: self.tick[0])
        self.assertEqual(second.observe(signals), [])

    def test_rejection_and_uncertain_set_never_auto_repeat(self):
        for result in (
            "revisao_rejeitar",
            "resultado_indeterminado",
            "bloqueado_erro",
            "habilitacao_nao_confirmada",
        ):
            self.tracker.observe({})
            self.tracker.observe({"interface:ether5": "admin=2"})
            self.tracker.complete(["interface:ether5"], result)
            self.tick[0] += 10000
            self.assertEqual(self.tracker.observe({"interface:ether5": "admin=2"}), [])

    def test_temporary_api_failure_reanalyses_only_after_interval(self):
        self.tracker.observe({"cpu": "acima_do_limiar"})
        self.tracker.complete(["cpu"], "pendente_revisao_gpt")
        self.tick[0] += 599
        self.assertEqual(self.tracker.observe({"cpu": "acima_do_limiar"}), [])
        self.tick[0] += 1
        self.assertEqual(self.tracker.observe({"cpu": "acima_do_limiar"}), ["cpu"])

    def test_resolution_then_recurrence_creates_new_episode(self):
        self.tracker.observe({"cpu": "acima_do_limiar"})
        old = self.tracker.entries["cpu"]["id"]
        self.tracker.complete(["cpu"], "sem_acao_executavel")
        self.tracker.observe({})
        self.assertEqual(self.tracker.observe({"cpu": "acima_do_limiar"}), ["cpu"])
        self.assertNotEqual(self.tracker.entries["cpu"]["id"], old)

    def test_collection_gap_does_not_reopen_rejected_known_incident(self):
        self.tracker.observe({"interface:ether5": "admin=2"})
        self.tracker.complete(["interface:ether5"], "cancelado_operador")
        self.tracker.observe({"interface:ether5": "dados_indisponiveis"})
        self.assertIn("interface:ether5", self.tracker.entries)
        self.assertEqual(self.tracker.observe({"interface:ether5": "admin=2"}), [])

    def test_other_incident_does_not_reoffer_refused_action(self):
        self.tracker.observe({"interface:ether5": "admin=2"})
        self.tracker.complete(["interface:ether5"], "cancelado_operador")
        self.assertEqual(
            self.tracker.observe({"interface:ether5": "admin=2", "cpu": "acima_do_limiar"}), ["cpu"]
        )

    def test_explicit_reset_reopens_incident(self):
        self.tracker.observe({"cpu": "acima_do_limiar"})
        self.tracker.complete(["cpu"], "sem_acao_executavel")
        second = IncidentTracker(self.path, self.profile, reset=True)
        self.assertEqual(second.observe({"cpu": "acima_do_limiar"}), ["cpu"])

    def test_two_monitors_cannot_share_state(self):
        lock = Path(self.temp.name) / "agent.lock"
        with MonitorLock(lock):
            with self.assertRaises(ValueError):
                with MonitorLock(lock):
                    self.fail()
        self.assertFalse(lock.exists())


class BindingTests(unittest.TestCase):
    def test_detected_ether5_uses_qwen_plan_without_operator_target(self):
        p, prep, ss, details = support.OperationalPlanTests().sample()
        result = bind_detected_plan(p, prep, ss, details, load_profile())
        self.assertEqual(result["objetivo_operador"]["tipo"], "manter_estado_desejado")
        self.assertEqual(result["plano_operacional_qwen"]["acao"], "habilitar_ether5")
        self.assertEqual(
            proposal_schema(result)["properties"]["acao"]["enum"], ["habilitar_ether5"]
        )

    def test_suppressed_or_profile_disabled_action_never_reappears(self):
        p, prep, ss, details = support.OperationalPlanTests().sample()
        result = bind_detected_plan(p, prep, ss, details, load_profile(), [])
        self.assertEqual(result["acoes_elegiveis_python"], [])
        profile = load_profile()
        profile["interfaces"]["ether5"]["propor_habilitacao"] = False
        self.assertEqual(
            bind_detected_plan(p, prep, ss, details, profile)["acoes_elegiveis_python"], []
        )

    def test_no_invalid_plan_can_create_restoration(self):
        p, prep, ss, details = support.OperationalPlanTests().sample()
        prep["resultado"] = "bloqueado_ou_inconclusivo"
        with self.assertRaises(ValueError):
            bind_detected_plan(p, prep, ss, details, load_profile())


class ContinuousIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(
        self,
        disabled=(),
        linkdown=(),
        answer="s",
        review_status="concluida",
        decision="aprovar",
        cycles=1,
        metrics=None,
        execute=True,
        before_cycle=None,
        limit=10,
        wan_sample=None,
        model_failure=False,
    ):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name)
        data = fresh_states()
        for name in disabled:
            data[name].update(admin_status=2, oper_status=2)
        for name in linkdown:
            data[name]["oper_status"] = 2
        dev = Device(data)

        async def connect():
            pass

        dev.connect = connect
        dev.close = lambda: None

        class Main:
            host = "192.168.88.1"

            async def connect(self):
                pass

            def close(self):
                pass

        class Backend:
            metadata = {"modelo": "simulado"}

            def __init__(self):
                self.calls = []

            async def chat(self, messages, tools=None, schema=None):
                self.calls.append((messages, schema))
                if model_failure:
                    raise module.AgentError("Modelo local indisponivel no ensaio.")
                if tools:
                    content = {"content": "PRONTO"}
                elif "admin_status_lido" in schema.get("properties", {}):
                    row = json.loads(messages[1]["content"])
                    state = dev.data[row["interface"]]
                    content = {
                        "content": json.dumps(
                            {
                                "admin_status_lido": state["admin_status"],
                                "oper_status_lido": state["oper_status"],
                                "evidencia": row["evidencia"],
                                "acao": expected_action(state),
                            }
                        )
                    }
                else:
                    action = schema["properties"]["acao"]["enum"][0]
                    doc = {
                        "resumo": "Estados atuais observados; causa nao determinada.",
                        "hipoteses": [],
                        "evidencias": schema["properties"]["evidencias"]["items"]["enum"],
                        "acao": action,
                        "justificativa": "Restaurar estado desejado, com consentimento posterior."
                        if action.startswith("habilitar")
                        else "Sem restauracao administrativa elegivel.",
                        "limitacoes": [],
                        "proximas_verificacoes": [],
                    }
                    if "problemas_identificados" in schema["properties"]:
                        view = json.loads(messages[1]["content"])
                        doc["problemas_identificados"] = [
                            {
                                "id": f["id"],
                                "explicacao": "Achado observado; causa adicional nao determinada.",
                            }
                            for f in view["problemas_observados"]
                        ]
                        if view.get("verificacoes_disponiveis"):
                            doc["proximas_verificacoes"] = [
                                view["verificacoes_disponiveis"][0]["id"]
                            ]
                    content = {"content": json.dumps(doc)}
                return {"message": content}

        class Review:
            key = "API_SECRET"
            model = "simulado"

            def __init__(self):
                self.calls = []

            async def review(self, p, doc, pid, ids):
                self.calls.append((p, doc))
                opinion_doc = opinion(pid, decision, doc["acao"])
                opinion_doc["evidencias"] = [ids[0]]
                if "fatos_conferiveis" in p:
                    opinion_doc.update(avaliacao_factual="sem_erro_identificado", erros_factuais=[])
                return {
                    "status": review_status,
                    "parecer": opinion_doc if review_status == "concluida" else None,
                    "contingencia_elegivel": False,
                }

        values = metrics or {
            "tem_dados": True,
            "cpu_media_pct": 1,
            "cpu_indices_pct": {"1": 1},
            "memoria_pct": 24,
        }

        async def execute_tool(tools, name, arguments):
            if name == "consultar_estado_wan":
                return dict(copy.deepcopy(wan_sample), utc=utcnow()), []
            if name == "ler_historico":
                return {"tem_dados": False, "serie": []}, []
            if name == "consultar_cpu_memoria":
                return values, []
            if name == "consultar_interface":
                row = next(s for s in dev.data.values() if s["ifindex"] == arguments["ifindex"])
                return {"tem_dados": True, **row}, []
            return {"tem_dados": False}, []

        args = module.parser().parse_args(["--sem-logs", "--ciclos", str(cycles)])
        args.profile = load_profile()
        args.context = load_context()
        args.banco = folder / "monitoramento.db"
        args.executar_correcoes = execute
        args.observacao_wan_habilitada = wan_sample is not None

        class Observer:
            async def connect(self):
                pass

            def close(self):
                pass

        tracker = IncidentTracker(folder / "incidentes.json", args.profile)
        backend = Backend()
        rev = Review()
        prompts = []
        session = {"tentativas": 0, "limite": limit}
        results = []

        async def supervised(*args, **kwargs):
            def ask(prompt):
                prompts.append(prompt)
                return answer

            return await real_supervise(*args, **kwargs, ask=ask, pause=0)

        with (
            patch.object(module, "BASE", folder),
            patch.object(module, "Client", return_value=Main()),
            patch.object(module, "InterfaceClient", return_value=dev),
            patch.object(module.TemporalTools, "execute", execute_tool),
            patch.object(module, "supervise", supervised),
            patch.object(module, "WANObserver", return_value=Observer()),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for cycle_index in range(cycles):
                if before_cycle:
                    before_cycle(cycle_index, dev, folder)
                for state in dev.data.values():
                    state["utc"] = utcnow()
                results.append(
                    await module.cycle(
                        args,
                        backend,
                        rev,
                        "READ_SECRET1",
                        "READ_SECRET2",
                        ("WRITE_SECRET1", "WRITE_SECRET2"),
                        session,
                        tracker,
                    )
                )
        files = list((folder / "dados" / "analises_supervisionadas").glob("*.json"))
        docs = [json.loads(p.read_text()) for p in files]
        return SimpleNamespace(
            results=results,
            dev=dev,
            backend=backend,
            rev=rev,
            prompts=prompts,
            docs=docs,
            folder=folder,
            tracker=tracker,
        )

    async def test_normal_does_not_call_models_api_or_writer(self):
        r = await self.scenario(cycles=2)
        self.assertEqual(len(r.backend.calls), 0)
        self.assertEqual(r.rev.calls, [])
        self.assertEqual(r.dev.writes, [])
        self.assertTrue(all(x["resultado"] == "monitoramento_sem_desvio" for x in r.results))

    async def test_auto_detect_restore_confirm_then_remain_quiet(self):
        r = await self.scenario(disabled=["ether5"], cycles=3)
        self.assertEqual(r.results[0]["resultado"], "habilitacao_confirmada")
        self.assertEqual(r.dev.writes, [6])
        self.assertEqual(len(r.prompts), 1)
        self.assertEqual(len(r.rev.calls), 1)
        self.assertEqual(r.rev.calls[0][0]["objetivo_operador"]["tipo"], "manter_estado_desejado")
        self.assertEqual(r.results[-1]["resultado"], "monitoramento_sem_desvio")
        self.assertTrue(
            any(
                e["evento"] == "investigacao_SNMP" and e["origem"] == "programa_cobertura"
                for d in r.docs
                for e in d.get("investigacao_interfaces", {}).get("eventos", [])
            )
        )
        for secret in ("READ_SECRET1", "WRITE_SECRET1", "API_SECRET"):
            self.assertNotIn(secret, json.dumps(r.docs))

    async def test_human_no_is_not_asked_again_next_cycle(self):
        r = await self.scenario(disabled=["ether5"], answer="n", cycles=3)
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(len(r.prompts), 1)
        self.assertEqual(len(r.rev.calls), 1)
        self.assertEqual(r.results[-1]["resultado"], "monitoramento_sem_nova_analise")

    async def test_simulation_never_prompts_or_writes(self):
        r = await self.scenario(disabled=["ether5"], execute=False)
        self.assertEqual(r.results[0]["resultado"], "simulacao_proposta_revisada")
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])

    async def test_reviewer_failure_blocks_and_does_not_repeat_each_cycle(self):
        r = await self.scenario(disabled=["ether5"], review_status="timeout", cycles=3)
        self.assertEqual(r.results[0]["resultado"], "pendente_revisao_gpt")
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(len(r.rev.calls), 1)

    async def test_rejection_blocks_and_is_not_repeated(self):
        r = await self.scenario(disabled=["ether5"], decision="rejeitar", cycles=2)
        self.assertEqual(r.results[0]["resultado"], "revisao_rejeitar")
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(len(r.rev.calls), 2)

    async def test_wan_already_enabled_with_link_down_has_no_set(self):
        r = await self.scenario(linkdown=["ether1"])
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(r.rev.calls[0][0]["acoes_elegiveis_python"], [])

    async def test_protected_management_is_detected_but_never_enabled(self):
        r = await self.scenario(disabled=["ether2"])
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(r.rev.calls[0][0]["acoes_elegiveis_python"], [])

    async def test_cpu_high_does_not_trigger_an_interface_set(self):
        r = await self.scenario(metrics={"tem_dados": True, "cpu_media_pct": 95, "memoria_pct": 24})
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(len(r.rev.calls), 1)

    async def test_two_disabled_ports_prioritize_wan_and_defer_bench_with_cooldown(self):
        r = await self.scenario(disabled=["ether1", "ether5"], cycles=2)
        self.assertEqual(r.dev.writes, [2])
        self.assertEqual(len(r.prompts), 1)
        self.assertEqual(r.results[1]["resultado"], "intervalo_SET_300s")

    async def test_new_incident_after_cooldown_requires_a_new_confirmation(self):
        def elapsed(index, dev, folder):
            if index == 1:
                control = folder / "dados" / "atuacao" / "controle" / "ultima_tentativa_ether5.json"
                saved = json.loads(control.read_text())
                saved["epoch"] -= 301
                control.write_text(json.dumps(saved))

        r = await self.scenario(disabled=["ether1", "ether5"], cycles=2, before_cycle=elapsed)
        self.assertEqual(r.dev.writes, [2, 6])
        self.assertEqual(len(r.prompts), 2)
        self.assertEqual([x["resultado"] for x in r.results], ["habilitacao_confirmada"] * 2)

    async def test_session_cap_blocks_next_incident_even_with_elapsed_cooldown(self):
        r = await self.scenario(disabled=["ether1", "ether5"], cycles=2, limit=1)
        self.assertEqual(r.dev.writes, [2])
        self.assertEqual(len(r.prompts), 1)
        self.assertEqual(r.results[1]["resultado"], "limite_SET_sessao")

    async def test_no_snmp_data_does_not_become_health_or_write(self):
        r = await self.scenario(metrics={"tem_dados": False})
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])


class LogFocusTests(unittest.TestCase):
    def test_incident_logs_take_priority_over_unrelated_old_query(self):
        from contexto_supervisionado import make_packet

        def evidence(eid, origin, port):
            return {
                "id": eid,
                "utc": utcnow(),
                "ferramenta": "consultar_logs_arquivados",
                "origem": origin,
                "dados": {
                    "ultima_coleta_utc": utcnow(),
                    "resultado_ultima_coleta": "snapshot_completo",
                    "registros": [
                        {
                            "referencia": "LOG-" + str(i),
                            "message": port + " link down",
                            "topics": "interface;info",
                            "router_time": "2026-10-18 19:00:00",
                        }
                        for i in range(4)
                    ],
                },
            }

        agent = SimpleNamespace(
            context=load_context(),
            record={
                "ferramentas": [
                    evidence("E0", "IA", "ether3"),
                    evidence("E1", "programa_cobertura_incidente", "ether5"),
                ]
            },
        )
        agent.context["fuso_logs"] = "-03:00"
        packet = make_packet(agent, [], {}, {}, utcnow())
        self.assertEqual(len(packet["logs"]["eventos"]), 4)
        self.assertTrue(all(row["chave"].startswith("E1/") for row in packet["logs"]["eventos"]))


class CommandTests(unittest.TestCase):
    def test_plain_command_is_continuous_and_supervised(self):
        a = module.parser().parse_args([])
        self.assertEqual(a.ciclos, 0)
        self.assertTrue(a.executar_correcoes)
        self.assertIsNone(a.restaurar_interface)
        self.assertEqual(a.fuso_logs, "-03:00")

    def test_simulation_optout(self):
        self.assertFalse(module.parser().parse_args(["--simular"]).executar_correcoes)

    def test_cooldown_and_session_limits_remain_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            control = folder / "controle"
            control.mkdir()
            p = control / "ultima_tentativa_ether5.json"
            p.write_text(json.dumps({"epoch": 1000}))
            self.assertEqual(
                write_hold(folder, {"tentativas": 0, "limite": 10}, 1100), "intervalo_SET_300s"
            )
            self.assertIsNone(write_hold(folder, {"tentativas": 0, "limite": 10}, 1301))
            self.assertEqual(
                write_hold(folder, {"tentativas": 10, "limite": 10}, 1301), "limite_SET_sessao"
            )
