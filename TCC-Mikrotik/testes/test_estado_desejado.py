import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from validacao_diagnostico import explicit_state_errors
from supervisao import supervise
from test_supervisionado import packet, proposal, opinion, FakeAgent
from test_investigacao_interfaces import Device
from snmp_ether5 import utcnow

FIXTURE = Path(__file__).resolve().parent.parent / "casos/estado_desejado_v057_real.json"


class TargetStateTests(unittest.TestCase):
    def setUp(self):
        self.real = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_both_real_proposals_do_not_confuse_desired_and_observed(self):
        for doc in self.real["propostas"]:
            with self.subTest(action=doc["acao"], summary=doc["resumo"]):
                self.assertEqual(explicit_state_errors(doc, self.real), [])

    def test_adjacent_target_labels_are_not_current_readings(self):
        for label in (
            "estado desejado",
            "estado administrativo desejado",
            "estado esperado",
            "valor alvo",
            "status desejado",
        ):
            for punctuation in (" ", ": ", " ("):
                text = (
                    "ether5 apresenta admin_status=2; " + label + punctuation + "admin_status=1)."
                )

                text = text.replace(";", ",")
                with self.subTest(text=text):
                    self.assertEqual(explicit_state_errors({"resumo": text}, self.real), [])

    def test_target_label_does_not_hide_earlier_wrong_observation(self):
        doc = {
            "resumo": "ether5 apresenta admin_status=1, divergente do estado desejado (admin_status=2)."
        }
        errors = explicit_state_errors(doc, self.real)
        self.assertEqual(len(errors), 1)
        self.assertEqual((errors[0]["valor_texto"], errors[0]["valor_SNMP"]), (1, 2))

    def test_target_label_does_not_hide_later_wrong_observation(self):
        doc = {
            "resumo": "O estado desejado de ether5 e admin_status=1, mas a leitura atual apresenta admin_status=1."
        }
        self.assertTrue(explicit_state_errors(doc, self.real))

    def test_desired_admin_does_not_hide_wrong_oper_in_same_sentence(self):
        doc = {
            "resumo": "ether5 tem admin_status=2, estado desejado (admin_status=1), mas oper_status=1."
        }
        errors = explicit_state_errors(doc, self.real)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["metrica"], "oper_status")

    def test_wrong_current_state_still_blocked_in_each_audited_field(self):
        for field in ("resumo", "justificativa", "limitacoes", "problemas_identificados"):
            text = "ether5 apresenta admin_status=1."
            value = (
                [text]
                if field == "limitacoes"
                else (
                    [{"id": "D0", "explicacao": text}]
                    if field == "problemas_identificados"
                    else text
                )
            )
            with self.subTest(field=field):
                self.assertTrue(explicit_state_errors({field: value}, self.real))


class TargetStateGateTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(self, decision="aprovar", answer="s", execute=True):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            dev = Device()
            dev.data["ether5"].update(admin_status=2, oper_status=2)
            for row in dev.data.values():
                row["utc"] = utcnow()
            p = packet()
            p["objetivo_operador"] = {"tipo": "manter_estado_desejado"}
            p["evidencias"][0]["ferramenta"] = "consultar_cpu_memoria"
            p["problemas_observados"] = [
                {"id": "D0", "proxima_verificacao": "Conferir estado desejado."}
            ]
            doc = proposal()
            doc["problemas_identificados"] = [
                {
                    "id": "D0",
                    "explicacao": "Ether5 apresenta admin_status=2, divergente do estado desejado (admin_status=1).",
                }
            ]
            doc["proximas_verificacoes"] = ["V0"]

            class Reviewer:
                def __init__(self):
                    self.calls = 0

                async def review(self, p, d, pid, ids):
                    self.calls += 1
                    result = opinion(pid, decision=decision, action=d["acao"])
                    result.update(avaliacao_factual="sem_erro_identificado", erros_factuais=[])
                    return {
                        "status": "concluida",
                        "parecer": result,
                        "contingencia_elegivel": False,
                    }

            rev = Reviewer()
            prompts = []
            agent = FakeAgent(folder / "r.json", doc)
            with contextlib.redirect_stdout(io.StringIO()):
                result = await supervise(
                    agent,
                    dev,
                    dev if execute else None,
                    p,
                    copy.deepcopy(dev.data),
                    rev,
                    execute,
                    False,
                    folder,
                    {"tentativas": 0},
                    ask=lambda q: prompts.append(q) or answer,
                    pause=0,
                    feedback_enabled=False,
                )
            return result, dev.writes, rev.calls, prompts

    async def test_correct_target_passes_review_and_confirmed_executor(self):
        result, writes, calls, prompts = await self.scenario()
        self.assertEqual(result["resultado"], "habilitacao_confirmada")
        self.assertEqual(writes, [6])
        self.assertEqual(calls, 1)
        self.assertEqual(len(prompts), 1)

    async def test_human_rejection_still_prevents_set(self):
        result, writes, calls, prompts = await self.scenario(answer="n")
        self.assertEqual(result["resultado"], "cancelado_operador")
        self.assertEqual(writes, [])
        self.assertEqual(calls, 1)
        self.assertEqual(len(prompts), 1)

    async def test_gpt_rejection_still_prevents_consent_and_set(self):
        result, writes, calls, prompts = await self.scenario(decision="rejeitar")
        self.assertEqual(result["resultado"], "revisao_rejeitar")
        self.assertEqual(writes, [])
        self.assertEqual(calls, 1)
        self.assertEqual(prompts, [])

    async def test_simulation_never_prompts_or_writes(self):
        result, writes, calls, prompts = await self.scenario(execute=False)
        self.assertEqual(result["resultado"], "simulacao_proposta_revisada")
        self.assertEqual(writes, [])
        self.assertEqual(calls, 1)
        self.assertEqual(prompts, [])


if __name__ == "__main__":
    unittest.main()
