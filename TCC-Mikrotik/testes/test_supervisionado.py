import contextlib
import copy
import io
import json
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

from contexto_supervisionado import temporal_summary, sanitize, make_packet
from revisor_gpt import GPTReviewer, APIProblem, request_api, validate_review
from supervisao import supervise, validate_proposal
from test_investigacao_interfaces import Device, states
from snmp_ether5 import utcnow


def packet(name="ether5"):
    return {
        "pergunta": "Compare CPU com historico sem inventar causa.",
        "referencia_utc": utcnow(),
        "evidencias": [{"id": "E0", "utc": utcnow(), "dados": {"cpu_media_pct": 27.25}}],
        "interfaces": [
            {
                "evidencia": "I1",
                "interface": name,
                "ifindex": 6 if name == "ether5" else 2,
                "admin_status": 2,
                "oper_status": 2,
                "idade_s": 1,
            }
        ],
        "logs": {"eventos": []},
        "acoes_elegiveis_python": [{"id": "habilitar_" + name, "interface": name}]
        if name != "ether2"
        else [],
    }


def proposal(action="habilitar_ether5"):
    return {
        "resumo": "Porta desabilitada no cenario declarado.",
        "hipoteses": [],
        "evidencias": ["E0", "I1"],
        "acao": action,
        "justificativa": "Propor habilitacao administrativa.",
        "limitacoes": ["Nao prova recuperacao do link."],
        "proximas_verificacoes": [],
    }


def opinion(pid, decision="aprovar", action="habilitar_ether5"):
    return {
        "proposta_id": pid,
        "decisao": decision,
        "justificativa": "Compativel no escopo.",
        "evidencias": ["E0", "I1"],
        "dados_faltantes": [],
        "acao_avaliada": action,
        "coerencia_acao_justificativa": "coerente",
        "adequacao_objetivo": "adequada",
    }


class FakeAgent:
    def __init__(self, path, doc):
        self.log_path = path
        self.record = {}
        self.doc = doc
        self.tools = SimpleNamespace(clean=lambda x: x)

    def save(self):
        self.log_path.write_text(json.dumps(self.record), encoding="utf-8")

    async def chat(self, *args, **kwargs):
        return {"content": json.dumps(self.doc)}


class Reviewer:
    def __init__(self, status="concluida", decision="aprovar", on_review=None):
        self.status = status
        self.decision = decision
        self.on_review = on_review
        self.calls = 0

    async def review(self, packet, proposal, pid, ids):
        self.calls += 1
        if self.on_review:
            self.on_review()
        return {
            "status": self.status,
            "parecer": opinion(pid, self.decision, proposal["acao"])
            if self.status == "concluida"
            else None,
            "contingencia_elegivel": self.status == "timeout",
        }


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(
        self,
        decision="aprovar",
        status="concluida",
        answer="s",
        execute=True,
        contingency=False,
        action="habilitar_ether5",
        on_ask=None,
        elapsed=False,
    ):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            d = Device()
            d.data["ether5"].update(admin_status=2, oper_status=2)
            for s in d.data.values():
                s["utc"] = utcnow()
            initial = copy.deepcopy(d.data)
            a = FakeAgent(folder / "r.json", proposal(action))
            p = packet()
            if action == "habilitar_ether2":
                p = packet("ether2")
            count = [0]
            ticks = [0]

            def ask(msg):
                count[0] += 1
                if on_ask:
                    on_ask(d)
                if elapsed:
                    ticks[0] = 121
                return answer

            rev = Reviewer(status, decision)
            result = await supervise(
                a,
                d,
                d if execute else None,
                p,
                initial,
                rev,
                execute,
                contingency,
                folder,
                {"tentativas": 0},
                ask=ask,
                clock=lambda: ticks[0],
                pause=0,
            )
            return result, d, count[0], rev

    async def test_approve_human_get_set_get(self):
        r, d, n, _ = await self.run_case()
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertEqual(d.writes, [6])
        self.assertEqual(n, 1)
        kinds = [e["evento"] for e in r["eventos"]]
        for x, y in [
            ("revisao_remota_encerrada", "decisao_operador"),
            ("decisao_operador", "GET_pre_SET"),
            ("GET_pre_SET", "SET_a_enviar"),
            ("SET_a_enviar", "GET_pos_SET"),
        ]:
            self.assertLess(kinds.index(x), kinds.index(y))

    async def test_no_human_consent_no_set(self):
        for answer in ("", "n", "nao", "yes please"):
            r, d, _, _ = await self.run_case(answer=answer)
            self.assertEqual(d.writes, [])
            self.assertEqual(r["resultado"], "cancelado_operador")

    async def test_yes_variants(self):
        for answer in ("Y", "sim", "yes", "S"):
            r, d, _, _ = await self.run_case(answer=answer)
            self.assertEqual(d.writes, [6])

    async def test_rejection_is_never_offline_fallback(self):
        for decision in ("rejeitar", "solicitar_dados"):
            r, d, n, _ = await self.run_case(decision=decision, contingency=True)
            self.assertEqual(d.writes, [])
            self.assertEqual(n, 0)
            self.assertEqual(r["resultado"], "revisao_" + decision)

    async def test_timeout_without_optin_pending(self):
        r, d, n, _ = await self.run_case(status="timeout")
        self.assertEqual(r["resultado"], "pendente_revisao_gpt")
        self.assertEqual(d.writes, [])
        self.assertEqual(n, 0)

    async def test_fallback_requires_exact_local_confirmation(self):
        r, d, _, _ = await self.run_case(status="timeout", contingency=True, answer="s")
        self.assertEqual(d.writes, [])
        r, d, _, _ = await self.run_case(status="timeout", contingency=True, answer="LOCAL ether5")
        self.assertEqual(d.writes, [6])
        self.assertEqual(r["resultado"], "habilitacao_confirmada")

    async def test_bad_key_quota_refusal_invalid_never_fallback(self):
        for status in (
            "credencial_invalida",
            "cota_insuficiente",
            "recusa_modelo",
            "resposta_invalida",
            "chave_ausente",
        ):
            r, d, n, _ = await self.run_case(status=status, contingency=True, answer="LOCAL ether5")
            self.assertEqual(d.writes, [])
            self.assertEqual(n, 0)

    async def test_simulation_reviews_but_never_prompts_or_writes(self):
        r, d, n, rev = await self.run_case(execute=False)
        self.assertEqual(rev.calls, 1)
        self.assertEqual(n, 0)
        self.assertEqual(d.writes, [])
        self.assertEqual(r["resultado"], "simulacao_proposta_revisada")

    async def test_state_changed_during_confirmation(self):
        r, d, _, _ = await self.run_case(on_ask=lambda d: d.data["ether5"].update(admin_status=1))
        self.assertEqual(d.writes, [])
        self.assertEqual(r["resultado"], "cancelado_estado_mudou_antes_SET")

    async def test_oper_change_also_cancels(self):
        r, d, _, _ = await self.run_case(on_ask=lambda d: d.data["ether5"].update(oper_status=3))
        self.assertEqual(d.writes, [])

    async def test_identity_change_blocks(self):
        r, d, _, _ = await self.run_case(
            on_ask=lambda d: d.data["ether5"].update(mac="00:00:00:00:00:00")
        )
        self.assertEqual(d.writes, [])
        self.assertEqual(r["resultado"], "bloqueado_erro")

    async def test_expired_approval_no_set(self):
        r, d, _, _ = await self.run_case(elapsed=True)
        self.assertEqual(d.writes, [])
        self.assertEqual(r["resultado"], "proposta_expirada_apos_aprovacao")

    async def test_ether2_not_in_catalogue_even_if_gpt_would_approve(self):
        r, d, n, rev = await self.run_case(action="habilitar_ether2")
        self.assertEqual(d.writes, [])
        self.assertEqual(rev.calls, 0)
        self.assertEqual(n, 0)

    async def test_cpu_recommendation_no_set(self):
        r, d, n, rev = await self.run_case(action="investigar")
        self.assertEqual(d.writes, [])
        self.assertEqual(n, 0)
        self.assertEqual(rev.calls, 1)

    async def test_post_get_timeout_not_success(self):
        r, d, _, _ = await self.run_case(on_ask=lambda d: setattr(d, "fail_post", True))
        self.assertEqual(d.writes, [6])
        self.assertEqual(r["resultado"], "resultado_indeterminado")

    async def test_lost_set_response_no_resend(self):
        r, d, _, _ = await self.run_case(
            on_ask=lambda d: setattr(
                d, "response", {"resultado": "indeterminado", "detalhe": "timeout"}
            )
        )
        self.assertEqual(d.writes, [6])
        self.assertEqual(r["resultado"], "habilitada_sem_confirmacao_SET")


class APITests(unittest.IsolatedAsyncioTestCase):
    async def test_responses_request_and_parse(self):
        seen = []

        def transport(payload, key, timeout):
            seen.append(payload)
            return {
                "status": "completed",
                "model": "modelo-real",
                "id": "r1",
                "usage": {"input_tokens": 100},
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(opinion("p"))}],
                    }
                ],
            }

        r = await GPTReviewer("secret", transport=transport).review(
            packet(), proposal(), "p", ["E0", "I1"]
        )
        self.assertEqual(r["status"], "concluida")
        self.assertFalse(seen[0]["store"])
        self.assertTrue(seen[0]["text"]["format"]["strict"])
        self.assertNotIn("secret", json.dumps(r))
        self.assertEqual(r["modelo_retornado"], "modelo-real")

    async def test_temporary_failure_retry_and_circuit(self):
        calls = []

        def transport(*_):
            calls.append(1)
            raise APIProblem("timeout")

        reviewer = GPTReviewer("k", transport=transport, clock=lambda: 10, sleeper=AsyncMock())
        r = await reviewer.review(packet(), proposal(), "p", ["E0", "I1"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(r["contingencia_elegivel"])
        r = await reviewer.review(packet(), proposal(), "p", ["E0", "I1"])
        self.assertEqual(r["status"], "circuito_aberto")
        self.assertEqual(len(calls), 2)

    async def test_401_no_retry_and_persistent(self):
        calls = []

        def transport(*_):
            calls.append(1)
            raise APIProblem("credencial_invalida", 401)

        reviewer = GPTReviewer("k", transport=transport)
        for _ in range(2):
            r = await reviewer.review(packet(), proposal(), "p", ["E0", "I1"])
            self.assertFalse(r["contingencia_elegivel"])
        self.assertEqual(len(calls), 1)

    async def test_missing_key_no_network(self):
        r = await GPTReviewer("", transport=lambda *_: self.fail()).review(
            packet(), proposal(), "p", ["E0", "I1"]
        )
        self.assertEqual(r["status"], "chave_ausente")

    async def test_refusal_incomplete_invalid_id_no_retry_or_fallback(self):
        responses = [
            {"status": "incomplete", "output": []},
            {
                "status": "completed",
                "output": [{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}],
            },
            {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(opinion("wrong"))}],
                    }
                ],
            },
        ]
        for response in responses:
            reviewer = GPTReviewer("k", transport=lambda *_: response)
            r = await reviewer.review(packet(), proposal(), "p", ["E0", "I1"])
            self.assertFalse(r["contingencia_elegivel"])
            self.assertEqual(len(r["tentativas"]), 1)
            self.assertNotEqual(r["status"], "concluida")

    def test_http_classification_without_sensitive_body_logging(self):
        for code, body, expected in [
            (401, b"secret", "credencial_invalida"),
            (429, b'{"error":{"code":"insufficient_quota"}}', "cota_insuficiente"),
            (429, b"{}", "limite_nao_identificado"),
            (503, b"{}", "servico_indisponivel"),
        ]:
            opener = SimpleNamespace(
                open=lambda *a, **kw: (_ for _ in ()).throw(
                    urllib.error.HTTPError("url", code, "secret", {}, io.BytesIO(body))
                )
            )
            with patch("urllib.request.build_opener", return_value=opener):
                with self.assertRaises(APIProblem) as caught:
                    request_api({}, "secret", 5)
                self.assertEqual(caught.exception.category, expected)
                self.assertNotIn("secret", str(caught.exception))

    def test_mismatched_or_contradictory_review_rejected(self):
        for doc in (
            dict(opinion("p"), dados_faltantes=["Precisa confirmar estado"]),
            dict(opinion("p"), evidencias=["FAKE"]),
        ):
            with self.assertRaises(ValueError):
                validate_review(doc, "p", ["E0", "I1"])


class TemporalTests(unittest.TestCase):
    def rows(self):
        ref = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
        return ref, [
            {
                "utc": (ref - timedelta(seconds=s)).isoformat(),
                "cpu_pct": 25 if s <= 300 else 1,
                "ram_pct": 24,
            }
            for s in range(0, 1200, 10)
        ]

    def test_summary_and_pp_no_claim_of_cause(self):
        ref, rows = self.rows()
        s = temporal_summary(rows, ref.isoformat())
        self.assertEqual(s["cpu_pct"]["variacao_media_pp"], 24)
        self.assertTrue(s["cpu_pct"]["comparacao_com_cobertura_minima"])

    def test_missing_old_future_and_gaps_not_baseline(self):
        ref, rows = self.rows()
        for subset in (
            rows[:6],
            rows[::10],
            [dict(rows[0], utc=(ref + timedelta(seconds=10)).isoformat())],
            rows[20:],
        ):
            s = temporal_summary(subset, ref.isoformat())
            self.assertIsNone(s["cpu_pct"]["variacao_media_pp"])

    def test_invalid_values_excluded_and_reported(self):
        ref, rows = self.rows()
        rows[0]["cpu_pct"] = True
        rows[1]["cpu_pct"] = 150
        s = temporal_summary(rows, ref.isoformat())
        self.assertEqual(s["cpu_pct"]["recente_0a300s"]["ausentes_ou_invalidas"], 2)
        self.assertIsNone(s["cpu_pct"]["variacao_media_pp"])

    def test_sanitize_retains_port_and_timestamp(self):
        text = "2026-10-14 ether1 admin@192.168.88.50 password=abcdef sk-abcDEF D0:EA:11:0B:47:E6"
        result = sanitize(text)
        for secret in ("192.168.88.50", "abcdef", "sk-abcDEF", "D0:EA:11:0B:47:E6", "admin@"):
            self.assertNotIn(secret, result)
        self.assertIn("ether1", result)
        self.assertIn("2026-10-14", result)
        self.assertNotIn("source=", sanitize("new script added source=abc"))

    def test_question_and_original_metric_evidence_preserved(self):
        ref, rows = self.rows()
        agent = SimpleNamespace(
            context={"limiar_cpu_pct": 85, "limiar_ram_pct": 85},
            record={
                "pergunta": "Explique a mudanca de CPU.",
                "ferramentas": [
                    {
                        "id": "E0",
                        "utc": ref.isoformat(),
                        "ferramenta": "ler_historico",
                        "dados": {"tem_dados": True, "serie": rows},
                    },
                    {
                        "id": "E1",
                        "utc": ref.isoformat(),
                        "ferramenta": "consultar_cpu_memoria",
                        "dados": {
                            "tem_dados": True,
                            "cpu_media_pct": 27.25,
                            "cpu_indices_pct": {"1": 29, "2": 2, "3": 48, "4": 30},
                            "memoria_pct": 23.63,
                        },
                    },
                ],
            },
        )
        p = make_packet(agent, [], {}, {}, ref.isoformat())
        self.assertEqual(p["pergunta"], "Explique a mudanca de CPU.")
        self.assertEqual(
            p["evidencias"][0]["dados"]["resumo_temporal"]["cpu_pct"]["variacao_media_pp"], 24
        )
        self.assertEqual(p["evidencias"][1]["dados"]["cpu_indices_pct"]["3"], 48)


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_entry_routes_simulation_and_remote_packet(self):
        import agente_supervisionado as module
        from politica_diagnostico import load_context

        calls = []

        class Backend:
            metadata = {"modelo": "fake"}

            async def chat(self, messages, tools=None, schema=None):
                calls.append((messages, schema))
                if tools:
                    msg = {"content": "PRONTO"}
                elif "admin_status_lido" in schema.get("properties", {}):
                    values = json.loads(messages[1]["content"])
                    msg = {
                        "content": json.dumps(
                            {
                                "admin_status_lido": values["admin_status"],
                                "oper_status_lido": values["oper_status"],
                                "evidencia": values["evidencia"],
                                "acao": "nenhuma",
                            }
                        )
                    }
                else:
                    msg = {
                        "content": json.dumps(dict(proposal("nenhuma"), evidencias=["E0", "I0"]))
                    }
                return {"message": msg}

        class Main:
            host = "192.168.88.1"

            async def connect(self):
                pass

            def close(self):
                pass

        class Ports(Device):
            async def connect(self):
                pass

            def close(self):
                pass

        async def tools_execute(self, name, args):
            if name == "ler_historico":
                return {
                    "tem_dados": True,
                    "serie": [{"utc": utcnow(), "cpu_pct": 27.25, "ram_pct": 23.63}],
                    "interfaces_ultimo_ciclo_max16": [
                        {"nome": n, "oper_status": 1, "ifindex": i}
                        for n, i in [("ether1", 2), ("ether2", 3)]
                    ],
                }, []
            return {
                "tem_dados": True,
                "cpu_media_pct": 27.25,
                "cpu_indices_pct": {"1": 29, "2": 2, "3": 48, "4": 30},
                "memoria_pct": 23.63,
            }, []

        class Review:
            key = "SUPER_SECRET"
            model = "fake"

            async def review(self, p, proposal, pid, ids):
                self.packet = p
                return {
                    "status": "concluida",
                    "parecer": dict(opinion(pid, action=proposal["acao"]), evidencias=["E0", "I0"]),
                    "contingencia_elegivel": False,
                }

        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            args = SimpleNamespace(
                host="192.168.88.1",
                usuario="tcc-monitor",
                banco=folder / "db",
                context=load_context(),
                sem_logs=True,
                executar_correcoes=False,
                contingencia_local=False,
                pergunta="Compare CPU com historico!",
            )
            rev = Review()
            dev = Ports()
            for s in dev.data.values():
                s["utc"] = utcnow()
            with (
                patch.object(module, "BASE", folder),
                patch.object(module, "Client", return_value=Main()),
                patch.object(module, "InterfaceClient", return_value=dev),
                patch.object(module.TemporalTools, "execute", tools_execute),
            ):
                await module.cycle(
                    args, Backend(), rev, "auth_SECRET", "priv_SECRET", None, {"tentativas": 0}
                )
            saved = json.loads(
                next((folder / "dados" / "analises_supervisionadas").glob("*.json")).read_text()
            )
            self.assertEqual(saved["versao"], "0.6.0")
            self.assertEqual(saved["supervisao"]["resultado"], "sem_acao_executavel")
            self.assertEqual(rev.packet["pergunta"], args.pergunta)
            self.assertEqual(dev.writes, [])
            self.assertNotIn("SUPER_SECRET", json.dumps(saved))
            self.assertTrue(
                any(
                    "cpu_indices_pct" in canonical_packet
                    for canonical_packet in [json.dumps(rev.packet)]
                )
            )
            self.assertLess(
                len(json.dumps(calls[-1][0], ensure_ascii=False))
                + len(json.dumps(calls[-1][1], ensure_ascii=False)),
                12500,
            )

    def test_history_limit_reads_120_and_preserves_default(self):
        import sqlite3
        from agente_ia import read_history

        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "db"
            db = sqlite3.connect(p)
            db.executescript(
                "CREATE TABLE ciclos(id INTEGER,roteador TEXT,instante_utc TEXT,status TEXT,diagnostico TEXT); CREATE TABLE metricas(ciclo_id INTEGER,escopo TEXT,metrica TEXT,valor REAL,bruto TEXT,entidade TEXT,status TEXT);"
            )
            for i in range(130):
                db.execute(
                    "INSERT INTO ciclos VALUES(?,?,?,?,?)",
                    (i, "192.168.88.1", utcnow(), "ok", "[]"),
                )
                db.execute(
                    "INSERT INTO metricas VALUES(?,?,?,?,?,?,?)",
                    (i, "sistema", "cpu_media_indices_pct", 25, None, None, "ok"),
                )
            db.commit()
            db.close()
            self.assertEqual(len(read_history(p, "192.168.88.1")["serie"]), 6)
            self.assertEqual(len(read_history(p, "192.168.88.1", 120)["serie"]), 120)


class PlanningBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_six_requests_with_two_slots_replays_user_failure(self):
        from agente_ia import Agent
        from agente_supervisionado import gather
        from politica_diagnostico import load_context

        calls = []

        def tool(name, args):
            return {"function": {"name": name, "arguments": args}}

        replies = [
            {"tool_calls": [tool("consultar_cpu_memoria", {})]},
            {"tool_calls": [tool("listar_interfaces", {})]},
            {
                "tool_calls": [
                    tool("consultar_interface", {"ifindex": i}) for i in (2, 3, 4, 5, 6, 7)
                ]
            },
        ]

        class Backend:
            metadata = {"modelo": "replay"}

            async def chat(self, *args, **kwargs):
                return {"message": replies.pop(0)}

        class Tools:
            logs_enabled = True

            def clean(self, x):
                return x

            async def execute(self, name, args):
                calls.append((name, args))
                if name == "ler_historico":
                    data = {
                        "tem_dados": True,
                        "serie": [{"utc": utcnow(), "cpu_pct": 0, "ram_pct": 24}],
                        "interfaces_ultimo_ciclo_max16": [
                            {"nome": n, "ifindex": i, "oper_status": 1}
                            for n, i in [("ether1", 2), ("ether2", 3)]
                        ],
                    }
                elif name == "consultar_cpu_memoria":
                    data = {"tem_dados": True, "cpu_media_pct": 0, "memoria_pct": 24}
                elif name == "consultar_interface":
                    data = {
                        "tem_dados": True,
                        "nome": "ether1" if args["ifindex"] == 2 else "ether2",
                        "oper_status": 1,
                        "ifindex": args["ifindex"],
                    }
                elif name == "consultar_logs_arquivados":
                    data = {"tem_dados": False, "registros": []}
                else:
                    data = {"tem_dados": True, "interfaces": []}
                return data, []

        with tempfile.TemporaryDirectory() as temp:
            a = Agent(Backend(), Tools(), Path(temp) / "r.json", load_context())
            result = await gather(a, "Analise CPU, interfaces e logs.")
            self.assertEqual(
                [args["ifindex"] for name, args in calls if name == "consultar_interface"], [2, 3]
            )
            self.assertEqual(a.record["chamadas_ferramentas_IA_executadas"], 4)
            self.assertTrue(a.record["limite_ferramentas_atingido"])
            self.assertEqual(a.record["limites_planejamento"][0]["omitidas"], 4)
            self.assertEqual(a.record["limites_planejamento"][0]["selecionadas_para_execucao"], 2)
            self.assertEqual(len(a.record["chamadas_modelo"][-1]["tool_calls"]), 6)
            self.assertEqual(a.record["diagnostico"]["classificacao"], "sem_anomalia_evidente")
            self.assertTrue(
                any(
                    e["ferramenta"] == "consultar_logs_arquivados"
                    and e["origem"] == "programa_cobertura_logs"
                    for e in result
                )
            )

    async def test_malformed_selected_request_never_executes_any_of_batch(self):
        from agente_ia import Agent, AgentError
        from agente_supervisionado import gather
        from politica_diagnostico import load_context

        executed = []

        class Backend:
            metadata = {}

            async def chat(self, *args, **kwargs):
                return {
                    "message": {
                        "tool_calls": [
                            {"function": {"name": "consultar_cpu_memoria", "arguments": {}}},
                            {"function": {"name": "consultar_interface", "arguments": "bad"}},
                        ]
                    }
                }

        class Tools:
            logs_enabled = False

            def clean(self, x):
                return x

            async def execute(self, name, args):
                executed.append(name)
                return {"tem_dados": False}, []

        with tempfile.TemporaryDirectory() as temp:
            a = Agent(Backend(), Tools(), Path(temp) / "r.json", load_context())
            with self.assertRaises(AgentError):
                await gather(a, "Teste")
            self.assertEqual(executed, ["ler_historico"])


class APIBillingTests(unittest.IsolatedAsyncioTestCase):
    async def test_billing_codes_persist_without_retry_or_contingency(self):
        codes = {
            "credit_balance_exhausted": "saldo_esgotado",
            "organization_spend_limit_exceeded": "limite_financeiro",
            "project_spend_limit_exceeded": "limite_financeiro",
            "organization_usage_limit_exceeded": "limite_uso_conta",
            "usage_limit_exceeded": "limite_uso_conta",
            "insufficient_quota": "cota_insuficiente",
        }
        for code, category in codes.items():
            calls = []

            def transport(*_):
                calls.append(1)
                body = json.dumps(
                    {"error": {"code": code, "message": "secret sensitive text"}}
                ).encode()
                opener = SimpleNamespace(
                    open=lambda *a, **kw: (_ for _ in ()).throw(
                        urllib.error.HTTPError("url", 429, "secret", {}, io.BytesIO(body))
                    )
                )
                with patch("urllib.request.build_opener", return_value=opener):
                    return request_api({}, "secret", 5)

            reviewer = GPTReviewer("secret", transport=transport, sleeper=AsyncMock())
            for _ in range(2):
                r = await reviewer.review(packet(), proposal(), "p", ["E0", "I1"])
                self.assertEqual(r["status"], category)
                self.assertEqual(r["codigo_api"], code)
                self.assertFalse(r["contingencia_elegivel"])
                self.assertNotIn("secret", json.dumps(r))
            self.assertEqual(len(calls), 1)

    async def test_unknown_429_is_not_assumed_transient(self):
        count = []

        def transport(*_):
            count.append(1)
            raise APIProblem("limite_nao_identificado", 429, "new_limit_code")

        r = await GPTReviewer("key", transport=transport).review(
            packet(), proposal(), "p", ["E0", "I1"]
        )
        self.assertEqual(len(count), 1)
        self.assertEqual(r["codigo_api"], "new_limit_code")
        self.assertFalse(r["contingencia_elegivel"])

    def test_rate_limit_code_remains_temporary(self):
        body = b'{"error":{"code":"rate_limit_exceeded"}}'
        opener = SimpleNamespace(
            open=lambda *a, **kw: (_ for _ in ()).throw(
                urllib.error.HTTPError("url", 429, "err", {}, io.BytesIO(body))
            )
        )
        with patch("urllib.request.build_opener", return_value=opener):
            with self.assertRaises(APIProblem) as caught:
                request_api({}, "secret", 5)
            self.assertEqual(caught.exception.category, "limite_temporario")
            self.assertEqual(caught.exception.code, "rate_limit_exceeded")

    async def test_no_action_without_review_is_explicitly_pending(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            a = FakeAgent(folder / "r.json", proposal("nenhuma"))
            r = await supervise(
                a,
                Device(),
                None,
                packet(),
                states(),
                Reviewer("limite_nao_identificado"),
                False,
                False,
                folder,
                {"tentativas": 0},
            )
            self.assertEqual(r["resultado"], "sem_acao_executavel_revisao_pendente")
            self.assertFalse(r["revisao_concluida"])

    def test_interface_detail_does_not_replace_wan_state(self):
        from contexto_supervisionado import make_packet

        a = SimpleNamespace(
            context={"limiar_cpu_pct": 85, "limiar_ram_pct": 85},
            record={
                "pergunta": "Analise interfaces",
                "ferramentas": [
                    {
                        "id": "E3",
                        "utc": utcnow(),
                        "ferramenta": "consultar_interface",
                        "dados": {
                            "tem_dados": True,
                            "nome": "ether3",
                            "ifindex": 4,
                            "admin_status": 1,
                            "oper_status": 2,
                            "rx_mbps": None,
                            "tx_mbps": None,
                        },
                    }
                ],
            },
        )
        current = states()
        for s in current.values():
            s["utc"] = utcnow()
        p = make_packet(a, [], current, {}, utcnow())
        table = {r["interface"]: r for r in p["interfaces"]}
        self.assertEqual(table["ether1"]["oper_status"], 1)
        self.assertEqual(table["ether3"]["oper_status"], 2)
        self.assertEqual(table["ether3"]["ifindex"], 4)
        self.assertEqual(table["ether3"]["evidencia"], "E3")


class EquivalentEvidenceTests(unittest.TestCase):
    def sample(self):
        p = packet()
        p["evidencias"].append(
            {
                "id": "E1",
                "ferramenta": "consultar_interface",
                "idade_consulta_s": 7.3,
                "dados": {
                    "tem_dados": True,
                    "nome": "ether5",
                    "ifindex": 6,
                    "admin_status": 2,
                    "oper_status": 2,
                },
            }
        )
        doc = proposal()
        doc["evidencias"] = ["E1"]
        return p, doc

    def test_live_same_port_reference_without_I1_citation_is_accepted(self):
        from contexto_supervisionado import action_references

        p, doc = self.sample()
        self.assertEqual(action_references(p, "ether5"), ["E1", "I1"])
        self.assertEqual(validate_proposal(doc, p)["acao"], "habilitar_ether5")
        self.assertEqual(doc["evidencias"], ["E1"])

    def test_original_investigation_reference_still_accepted(self):
        p, _ = self.sample()
        doc = proposal()
        doc["evidencias"] = ["I1"]
        self.assertEqual(validate_proposal(doc, p)["acao"], "habilitar_ether5")

    def test_different_port_index_or_states_cannot_substitute(self):
        for change in (
            {"nome": "ether1"},
            {"ifindex": 5},
            {"admin_status": 1},
            {"oper_status": 1},
            {"ifindex": True},
        ):
            p, doc = self.sample()
            p["evidencias"][-1]["dados"].update(change)
            with self.assertRaises(ValueError):
                validate_proposal(doc, p)

    def test_old_future_or_unknown_age_cannot_substitute(self):
        for age in (121, -1, None, float("nan")):
            p, doc = self.sample()
            p["evidencias"][-1]["idade_consulta_s"] = age
            with self.assertRaises(ValueError):
                validate_proposal(doc, p)

    def test_missing_old_or_basic_only_investigation_blocks_equivalence(self):
        for change in ({"evidencia": "I0"}, {"idade_s": 121}, {"idade_s": -1}, {"ifindex": None}):
            p, doc = self.sample()
            p["interfaces"][0].update(change)
            with self.assertRaises(ValueError):
                validate_proposal(doc, p)

    def test_logs_never_substitute_for_current_port_reference(self):
        p, doc = self.sample()
        p["logs"]["eventos"] = [{"chave": "E2/LOG-218"}]
        doc["evidencias"] = ["E2/LOG-218"]
        with self.assertRaises(ValueError):
            validate_proposal(doc, p)


class FeedbackTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(
        self, decisions, second=None, execute=True, contingency=False, expire=False, enabled=True
    ):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            d = Device()
            d.data["ether5"].update(admin_status=2, oper_status=2)
            for state in d.data.values():
                state["utc"] = utcnow()
            answers = []
            ticks = [0]

            class SequenceAgent(FakeAgent):
                def __init__(self, path):
                    super().__init__(path, proposal("investigar"))
                    self.prompts = []
                    self.outputs = [proposal("investigar"), second or proposal("habilitar_ether5")]

                async def chat(self, messages, **kwargs):
                    self.prompts.append(copy.deepcopy(messages))
                    return {"content": json.dumps(self.outputs.pop(0))}

            class SequenceReviewer:
                def __init__(self):
                    self.seen = []
                    self.steps = list(decisions)

                async def review(self, packet, proposal, pid, ids):
                    self.seen.append((copy.deepcopy(proposal), pid))
                    step = self.steps.pop(0)
                    if expire:
                        ticks[0] = 121
                    if step == "timeout":
                        return {"status": "timeout", "contingencia_elegivel": True, "parecer": None}
                    doc = opinion(pid, step, proposal["acao"])
                    if step == "rejeitar":
                        doc["justificativa"] = (
                            "A aprovacao humana vem depois da proposta; o objetivo declarado e restaurar a porta."
                        )
                    return {"status": "concluida", "contingencia_elegivel": False, "parecer": doc}

            a = SequenceAgent(folder / "r.json")
            rev = SequenceReviewer()

            def ask(prompt):
                answers.append(prompt)
                return "LOCAL ether5" if contingency else "s"

            r = await supervise(
                a,
                d,
                d if execute else None,
                packet(),
                copy.deepcopy(d.data),
                rev,
                execute,
                contingency,
                folder,
                {"tentativas": 0},
                ask=ask,
                clock=lambda: ticks[0],
                pause=0,
                feedback_enabled=enabled,
            )
            return r, d, a, rev, answers

    async def test_feedback_rejection_then_approval_one_set(self):
        r, d, a, rev, answers = await self.scenario(["rejeitar", "aprovar"])
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertEqual(d.writes, [6])
        self.assertEqual(len(answers), 1)
        self.assertEqual(len(r["rodadas"]), 2)
        self.assertEqual(r["rodadas"][0]["proposta_qwen"]["acao"], "investigar")
        self.assertEqual(r["rodadas"][0]["revisao_gpt"]["parecer"]["decisao"], "rejeitar")
        self.assertEqual(r["rodadas"][1]["proposta_qwen"]["acao"], "habilitar_ether5")
        self.assertIn("critica_gpt", a.prompts[1][-1]["content"])
        self.assertNotEqual(rev.seen[0][1], rev.seen[1][1])
        self.assertEqual(r["acao_apresentada"]["proposta_id"], rev.seen[1][1])

    async def test_second_rejection_no_third_round_or_consent(self):
        r, d, a, rev, answers = await self.scenario(["rejeitar", "rejeitar"])
        self.assertEqual(len(a.prompts), 2)
        self.assertEqual(len(rev.seen), 2)
        self.assertEqual(d.writes, [])
        self.assertEqual(answers, [])
        self.assertEqual(r["resultado"], "revisao_rejeitar")

    async def test_request_data_does_not_invent_or_retry(self):
        r, d, a, rev, answers = await self.scenario(["solicitar_dados"])
        self.assertEqual(len(a.prompts), 1)
        self.assertEqual(d.writes, [])
        self.assertEqual(answers, [])
        self.assertEqual(r["resultado"], "revisao_solicitar_dados")

    async def test_timeout_after_rejection_cannot_trigger_local_contingency(self):
        r, d, a, rev, answers = await self.scenario(["rejeitar", "timeout"], contingency=True)
        self.assertEqual(d.writes, [])
        self.assertEqual(answers, [])
        self.assertEqual(r["resultado"], "pendente_revisao_gpt")

    async def test_invalid_second_proposal_never_reaches_gpt_or_writer(self):
        second = proposal("habilitar_ether5")
        second["evidencias"] = ["FAKE"]
        r, d, a, rev, answers = await self.scenario(["rejeitar"], second=second)
        self.assertEqual(r["resultado"], "bloqueado_validacao_local")
        self.assertEqual(len(rev.seen), 1)
        self.assertEqual(d.writes, [])

    async def test_evidence_expiration_blocks_reformulation(self):
        r, d, a, rev, answers = await self.scenario(["rejeitar"], expire=True)
        self.assertEqual(r["resultado"], "evidencias_expiradas_antes_reformulacao")
        self.assertEqual(len(a.prompts), 1)
        self.assertEqual(d.writes, [])

    async def test_comparison_flag_keeps_single_review(self):
        r, d, a, rev, answers = await self.scenario(["rejeitar"], enabled=False)
        self.assertEqual(r["resultado"], "revisao_rejeitar")
        self.assertEqual(len(a.prompts), 1)
        self.assertFalse(r["reformulacao_habilitada"])
        self.assertEqual(d.writes, [])


class OperationalPlanTests(unittest.TestCase):
    def sample(self, disabled=True):
        current = states()
        details = {}
        if disabled:
            current["ether5"].update(admin_status=2, oper_status=2)
            details["I1"] = {"estado_final": copy.deepcopy(current["ether5"])}
        rows = []
        from investigacao_interfaces import expected_action

        for name, s in current.items():
            rows.append(
                {
                    "interface": name,
                    "admin_status_lido": s["admin_status"],
                    "oper_status_lido": s["oper_status"],
                    "evidencia": "I1" if name == "ether5" and disabled else "I0",
                    "acao": expected_action(s),
                }
            )
        prep = {
            "resultado": "simulacao_habilitacao_proposta_sem_SET"
            if disabled
            else "sem_correcao_administrativa_indicada",
            "plano_IA": {"avaliacoes": rows},
        }
        return packet(), prep, current, details

    def test_preserves_action_already_selected_by_qwen(self):
        from plano_operacional import bind_plan
        from supervisao import proposal_schema

        p, prep, current, details = self.sample()
        original = copy.deepcopy(prep)
        bound = bind_plan(p, prep, current, details, "ether5")
        self.assertEqual(bound["plano_operacional_qwen"]["acao"], "habilitar_ether5")
        self.assertEqual(
            bound["plano_operacional_qwen"]["avaliacao_original_qwen"],
            prep["plano_IA"]["avaliacoes"][2],
        )
        self.assertEqual(prep, original)
        self.assertEqual(proposal_schema(bound)["properties"]["acao"]["enum"], ["habilitar_ether5"])
        self.assertEqual(bound["objetivo_operador"]["admin_status_desejado"], 1)
        self.assertFalse(bound["objetivo_operador"]["link_exigido"])

    def test_redaction_cannot_replace_enable_by_none_or_investigate(self):
        from plano_operacional import bind_plan

        p, prep, current, details = self.sample()
        bound = bind_plan(p, prep, current, details, "ether5")
        for action in ("nenhuma", "investigar", "habilitar_ether1"):
            with self.assertRaises(ValueError):
                validate_proposal(proposal(action), bound)
        self.assertEqual(
            validate_proposal(proposal("habilitar_ether5"), bound)["acao"], "habilitar_ether5"
        )

    def test_monitoring_has_no_catalogue_of_writes(self):
        from plano_operacional import bind_plan

        p, prep, current, details = self.sample()
        bound = bind_plan(p, prep, current, details)
        self.assertEqual(bound["objetivo_operador"]["tipo"], "monitoramento")
        self.assertEqual(bound["acoes_elegiveis_python"], [])
        with self.assertRaises(ValueError):
            validate_proposal(proposal("habilitar_ether5"), bound)

    def test_already_enabled_preserves_none_no_enable(self):
        from plano_operacional import bind_plan

        p, prep, current, details = self.sample(False)
        bound = bind_plan(p, prep, current, details, "ether5")
        self.assertEqual(bound["plano_operacional_qwen"]["acao"], "nenhuma")
        self.assertEqual(bound["acoes_elegiveis_python"], [])

    def test_no_plan_or_unauthorized_interface_never_creates_enable(self):
        from plano_operacional import bind_plan

        p, prep, current, details = self.sample()
        for target in ("ether2", "ether3", "ether10"):
            with self.assertRaises(ValueError):
                bind_plan(p, prep, current, details, target)
        for result in ("em_andamento", "bloqueado_ou_inconclusivo"):
            with self.assertRaises(ValueError):
                bind_plan(p, dict(prep, resultado=result), current, details, "ether5")
        bad = copy.deepcopy(prep)
        bad["plano_IA"]["avaliacoes"][2]["acao"] = "nenhuma"
        with self.assertRaises(Exception):
            bind_plan(p, bad, current, details, "ether5")


class ExplicitReviewTests(unittest.IsolatedAsyncioTestCase):
    def test_approval_requires_matching_action_and_declared_consistency(self):
        from revisor_gpt import InconsistentReview

        base = opinion("p", action="habilitar_ether5")
        for change in (
            {"acao_avaliada": "nenhuma"},
            {"coerencia_acao_justificativa": "incoerente"},
            {"adequacao_objetivo": "inadequada"},
            {"adequacao_objetivo": "inconclusiva"},
        ):
            with self.assertRaises(InconsistentReview):
                validate_review(dict(base, **change), "p", ["E0", "I1"], "habilitar_ether5")
        self.assertEqual(
            validate_review(base, "p", ["E0", "I1"], "habilitar_ether5")["decisao"], "aprovar"
        )

    async def test_api_false_approval_is_blocked_and_never_fallback(self):
        def transport(*args):
            doc = dict(opinion("p"), coerencia_acao_justificativa="incoerente")
            return {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(doc)}],
                    }
                ],
            }

        r = await GPTReviewer("key", transport=transport).review(
            packet(), proposal(), "p", ["E0", "I1"]
        )
        self.assertEqual(r["status"], "parecer_inconsistente")
        self.assertFalse(r["contingencia_elegivel"])
        self.assertEqual(len(r["tentativas"]), 1)
        self.assertIn("incoerente", r["conteudo_original"])

    async def test_bound_plan_explanation_retry_keeps_action(self):
        from plano_operacional import bind_plan

        p, prep, current, details = OperationalPlanTests().sample()
        for s in current.values():
            s["utc"] = utcnow()
        bound = bind_plan(p, prep, current, details, "ether5")

        class Explainer(FakeAgent):
            def __init__(self, path):
                super().__init__(path, proposal())
                self.docs = [
                    dict(proposal(), resumo="Texto incoerente."),
                    dict(proposal(), resumo="Proposta administrativa, aprovacao posterior."),
                ]

            async def chat(self, *args, **kwargs):
                return {"content": json.dumps(self.docs.pop(0))}

        class Critic:
            def __init__(self):
                self.actions = []

            async def review(self, p, doc, pid, ids):
                self.actions.append(doc["acao"])
                decision = "rejeitar" if len(self.actions) == 1 else "aprovar"
                return {
                    "status": "concluida",
                    "parecer": opinion(pid, decision, doc["acao"]),
                    "contingencia_elegivel": False,
                }

        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            a = Explainer(folder / "r.json")
            rev = Critic()
            dev = Device(current)
            r = await supervise(
                a,
                dev,
                dev,
                bound,
                current,
                rev,
                True,
                False,
                folder,
                {"tentativas": 0},
                ask=lambda _: "s",
                pause=0,
            )
            self.assertEqual(r["resultado"], "habilitacao_confirmada")
            self.assertEqual(rev.actions, ["habilitar_ether5", "habilitar_ether5"])
            self.assertTrue(r["acao_copiada_do_plano_qwen"])
            self.assertEqual(dev.writes, [6])

    async def test_action_mismatch_even_approved_by_fake_reviewer_never_writes(self):
        class WrongReviewer:
            async def review(self, p, doc, pid, ids):
                return {
                    "status": "concluida",
                    "parecer": opinion(pid, action="nenhuma"),
                    "contingencia_elegivel": False,
                }

        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            d = Device()
            d.data["ether5"].update(admin_status=2)
            for s in d.data.values():
                s["utc"] = utcnow()
            a = FakeAgent(folder / "r.json", proposal())
            r = await supervise(
                a,
                d,
                d,
                packet(),
                copy.deepcopy(d.data),
                WrongReviewer(),
                True,
                True,
                folder,
                {"tentativas": 0},
                ask=lambda _: self.fail("Nao deveria pedir consentimento"),
                pause=0,
            )
            self.assertEqual(r["resultado"], "bloqueado_erro")
            self.assertEqual(d.writes, [])


class ObjectiveCLITests(unittest.TestCase):
    def test_write_uses_configured_profile_without_explicit_target(self):
        import agente_supervisionado as m

        args = m.parser().parse_args([])
        self.assertTrue(args.executar_correcoes)
        self.assertIsNone(args.restaurar_interface)
        self.assertEqual(args.ciclos, 0)

    def test_protected_interface_cannot_be_selected_as_restoration_goal(self):
        import agente_supervisionado as m

        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                m.parser().parse_args(["--restaurar-interface", "ether2"])
