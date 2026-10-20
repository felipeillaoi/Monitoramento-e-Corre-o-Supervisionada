import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from atuacao_controlada import run_scenario, WriteGuard, parse_proposal, explain
from resumir_atuacao import summarize
from snmp_ether5 import MAC, TestFailure

STATE = {
    "utc": "2026-10-11T18:22:05+00:00",
    "ifindex": 6,
    "descricao": "RouterOS RB750Gr3",
    "uptime_ticks": 1000,
    "nome": "ether5",
    "tipo": 6,
    "mac": MAC,
    "admin_status": 2,
    "oper_status": 2,
}


class FakeDevice:
    def __init__(self, state=None):
        self.state = copy.deepcopy(state or STATE)
        self.writes = []
        self.reply = {"resultado": "aceito", "detalhe": "noError"}
        self.change_on_set = True
        self.prechange = None
        self.fail_after = False

    async def discover(self):
        return self.state["ifindex"]

    async def snapshot(self, idx):
        if self.fail_after and self.writes:
            raise TimeoutError()
        return copy.deepcopy(self.state)

    async def enable(self, idx):
        self.writes.append(idx)
        if self.change_on_set:
            self.state["admin_status"] = 1
        return self.reply


class FakeAgent:
    def __init__(self, path, action="habilitar_ether5", callback=None, raw=None, observed=None):
        self.log_path = path
        self.record = {"chamadas_modelo": []}
        self.action, self.callback, self.raw = action, callback, raw
        self.observed = copy.deepcopy(observed or STATE)

    def save(self):
        self.log_path.write_text(json.dumps(self.record), encoding="utf-8")

    async def chat(self, *args, **kwargs):
        if self.callback:
            self.callback()
        self.record["chamadas_modelo"].append({})
        return {
            "content": self.raw
            if self.raw is not None
            else json.dumps(
                {
                    "acao": self.action,
                    "evidencia": "A0",
                    "admin_status_lido": self.observed["admin_status"],
                    "oper_status_lido": self.observed["oper_status"],
                }
            )
        }


class ActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    async def run_case(
        self,
        device=None,
        action="habilitar_ether5",
        execute=True,
        callback=None,
        raw=None,
        session=None,
        writer=True,
        clock=time.monotonic,
    ):
        d = device or FakeDevice()
        a = FakeAgent(self.root / "analise.json", action, callback, raw, d.state)
        state = session if session is not None else {"tentativas": 0}
        result = await run_scenario(
            a, d, d if writer else None, execute, self.root / "atuacao", state, pause=0, clock=clock
        )
        return result, d, a, state

    async def test_simulation_does_not_write(self):
        r, d, _, s = await self.run_case(execute=False)
        self.assertEqual(r["resultado"], "simulacao_habilitacao_proposta_sem_SET")
        self.assertEqual(d.writes, [])
        self.assertEqual(s["tentativas"], 0)

    async def test_valid_action_confirmed_and_journaled(self):
        r, d, a, s = await self.run_case()
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertEqual(d.writes, [6])
        self.assertEqual(s["tentativas"], 1)
        events = json.loads(Path(r["registro_atuacao"]).read_text())["eventos"]
        order = [e["evento"] for e in events]
        self.assertLess(order.index("SET_a_enviar"), order.index("resposta_SET"))
        intent = next(e for e in events if e["evento"] == "SET_a_enviar")
        self.assertEqual(intent["valor"], 1)
        self.assertEqual(intent["oid"], "1.3.6.1.2.1.2.2.1.7.6")
        self.assertEqual(a.record["atuacao_ether5"]["proposta_IA"]["acao"], "habilitar_ether5")

    async def test_up_without_cable_needs_no_action(self):
        r, d, _, _ = await self.run_case(FakeDevice(STATE | {"admin_status": 1}), action="nenhuma")
        self.assertEqual(r["resultado"], "nenhuma_acao_necessaria")
        self.assertEqual(d.writes, [])

    async def test_false_positive_model_blocked(self):
        r, d, _, _ = await self.run_case(FakeDevice(STATE | {"admin_status": 1}))
        self.assertEqual(r["resultado"], "bloqueado_divergencia_IA_politica")
        self.assertEqual(d.writes, [])

    async def test_model_omission_does_not_become_python_action(self):
        r, d, _, _ = await self.run_case(action="nenhuma")
        self.assertEqual(r["resultado"], "bloqueado_divergencia_IA_politica")
        self.assertEqual(d.writes, [])

    async def test_bad_identity_blocks_before_model(self):
        r, d, a, _ = await self.run_case(FakeDevice(STATE | {"mac": "00:00:00:00:00:00"}))
        self.assertEqual(d.writes, [])
        self.assertEqual(a.record["chamadas_modelo"], [])

    async def test_state_changed_during_model_cancels(self):
        d = FakeDevice()
        r, d, _, _ = await self.run_case(d, callback=lambda: d.state.update(admin_status=1))
        self.assertEqual(r["resultado"], "cancelado_estado_mudou_antes_do_SET")
        self.assertEqual(d.writes, [])

    async def test_index_changed_blocks(self):
        d = FakeDevice()
        r, d, _, _ = await self.run_case(d, callback=lambda: d.state.update(ifindex=7))
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")
        self.assertEqual(d.writes, [])

    async def test_bad_model_schema_blocks(self):
        r, d, _, _ = await self.run_case(raw='{"acao":"habilitar_ether1"}')
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")
        self.assertEqual(d.writes, [])

    async def test_session_limit(self):
        r, d, _, _ = await self.run_case(session={"tentativas": 1})
        self.assertEqual(r["resultado"], "bloqueado_limite_da_sessao")
        self.assertEqual(d.writes, [])

    async def test_missing_write_credentials(self):
        r, d, _, _ = await self.run_case(writer=False)
        self.assertEqual(r["resultado"], "bloqueado_sem_credencial_escrita")
        self.assertEqual(d.writes, [])

    async def test_persistent_cooldown_even_across_sessions(self):
        await self.run_case()
        r, d, _, _ = await self.run_case()
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")
        self.assertEqual(d.writes, [])

    async def test_lost_set_reply_is_not_claimed_success(self):
        d = FakeDevice()
        d.reply = {"resultado": "indeterminado", "detalhe": "timeout"}
        r, d, _, _ = await self.run_case(d)
        self.assertEqual(r["resultado"], "habilitada_sem_confirmacao_do_SET")
        self.assertEqual(d.writes, [6])

    async def test_ack_without_effect_not_success(self):
        d = FakeDevice()
        d.change_on_set = False
        r, d, _, _ = await self.run_case(d)
        self.assertEqual(r["resultado"], "habilitacao_nao_confirmada")

    async def test_post_read_failure_unknown(self):
        d = FakeDevice()
        d.fail_after = True
        r, d, _, _ = await self.run_case(d)
        self.assertEqual(r["resultado"], "resultado_indeterminado")

    async def test_model_delay_expires_evidence(self):
        moments = iter([100.0, 221.0])
        r, d, _, _ = await self.run_case(clock=lambda: next(moments))
        self.assertEqual(r["resultado"], "bloqueado_evidencia_inicial_antiga")
        self.assertEqual(d.writes, [])

    async def test_rejected_set_not_repeated(self):
        d = FakeDevice()
        d.change_on_set = False
        d.reply = {"resultado": "recusado", "detalhe": "noAccess"}
        r, d, _, _ = await self.run_case(d)
        self.assertEqual(r["resultado"], "SET_recusado")
        self.assertEqual(d.writes, [6])

    async def test_right_action_wrong_observation_blocks(self):
        raw = json.dumps(
            {
                "acao": "habilitar_ether5",
                "evidencia": "A0",
                "admin_status_lido": 1,
                "oper_status_lido": 2,
            }
        )
        r, d, _, _ = await self.run_case(raw=raw)
        self.assertEqual(r["resultado"], "bloqueado_estados_IA_divergentes")
        self.assertEqual(d.writes, [])

    async def test_legacy_free_text_is_rejected(self):
        raw = json.dumps(
            {
                "acao": "habilitar_ether5",
                "evidencia": "A0",
                "justificativa": "admin_status=2 significa habilitada",
            }
        )
        r, d, _, _ = await self.run_case(raw=raw)
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")
        self.assertEqual(d.writes, [])

    async def test_summary_does_not_count_intent_as_success(self):
        d = FakeDevice()
        d.fail_after = True
        r, _, _, _ = await self.run_case(d)
        doc = json.loads(Path(r["registro_atuacao"]).read_text())
        report = summarize([("exemplo.json", doc)])
        self.assertEqual(report["intencoes_SET"], 1)
        self.assertEqual(report["habilitacoes_confirmadas_nas_evidencias"], 0)

    async def test_summary_confirms_state_change(self):
        r, _, _, _ = await self.run_case()
        doc = json.loads(Path(r["registro_atuacao"]).read_text())
        report = summarize([("exemplo.json", doc)])
        self.assertEqual(report["habilitacoes_confirmadas_nas_evidencias"], 1)

    def test_verified_explanation_maps_disabled_correctly(self):
        text = explain(STATE)
        self.assertIn("administrativamente desabilitada", text)
        self.assertIn("estado operacional down", text)
        self.assertNotIn("ausencia de cabo", text)

    def test_boolean_status_is_not_integer_reading(self):
        with self.assertRaises(TestFailure):
            parse_proposal(
                json.dumps(
                    {
                        "acao": "nenhuma",
                        "evidencia": "A0",
                        "admin_status_lido": True,
                        "oper_status_lido": 2,
                    }
                )
            )


class GuardTests(unittest.TestCase):
    def test_concurrent_writer_blocked(self):
        with tempfile.TemporaryDirectory() as folder:
            with WriteGuard(folder):
                with self.assertRaises(TestFailure):
                    with WriteGuard(folder):
                        self.fail("Second writer admitted")

    def test_corrupt_state_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "ultima_tentativa_ether5.json").write_text("bad-json")
            with self.assertRaises(ValueError):
                with WriteGuard(folder):
                    self.fail("Corrupt state admitted")
            self.assertFalse(Path(folder, "ether5.lock").exists())

    def test_future_timestamp_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "ultima_tentativa_ether5.json").write_text(
                json.dumps({"epoch": time.time() + 60})
            )
            with self.assertRaises(TestFailure):
                with WriteGuard(folder):
                    self.fail("Clock inconsistency admitted")


class WiringTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_passes_mode_and_separate_credentials(self):
        from agente_ia import run_agent, Agent, fallback
        from politica_diagnostico import load_context

        for execute in (False, True):
            with self.subTest(execute=execute), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                args = SimpleNamespace(
                    host="192.168.88.1",
                    usuario="tcc-monitor",
                    banco=base / "db.sqlite",
                    context=load_context(),
                    pergunta="Teste",
                    cenario_ether5=True,
                    executar_correcoes=execute,
                    credenciais_escrita=("write-auth", "write-privacy"),
                    sessao_atuacao={"tentativas": 0},
                )
                legacy = Mock(connect=AsyncMock(), close=Mock())
                transports = []

                def factory(*credentials):
                    transport = Mock(connect=AsyncMock(), close=Mock())
                    transports.append((credentials, transport))
                    return transport

                outcome = {
                    "resultado": "nenhuma_acao_necessaria",
                    "eventos": [],
                    "registro_atuacao": str(base / "acao.json"),
                }
                with (
                    patch("agente_ia.BASE", base),
                    patch("agente_ia.Client", return_value=legacy),
                    patch.object(Agent, "run", new=AsyncMock(return_value=fallback("teste"))),
                    patch("snmp_ether5.Client", side_effect=factory),
                    patch(
                        "atuacao_controlada.run_scenario", new=AsyncMock(return_value=outcome)
                    ) as phase,
                ):
                    await run_agent(args, SimpleNamespace(metadata={}), "read-auth", "read-privacy")
                    self.assertEqual(transports[0][0], ("tcc-monitor", "read-auth", "read-privacy"))
                    self.assertEqual(len(transports), 2 if execute else 1)
                    self.assertIs(phase.call_args.args[3], execute)
                    if execute:
                        self.assertEqual(
                            transports[1][0], ("tcc-escrita", "write-auth", "write-privacy")
                        )
                    else:
                        self.assertIsNone(phase.call_args.args[2])
                    for _, transport in transports:
                        transport.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
