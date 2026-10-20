import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from validacao_diagnostico import (
    explicit_state_errors,
    verification_errors,
    install_verification_catalog,
)
from supervisao import proposal_schema, supervise
from test_supervisionado import packet, proposal, opinion, FakeAgent
from test_investigacao_interfaces import Device
from snmp_ether5 import utcnow

FIXTURE = Path(__file__).resolve().parent.parent / "casos" / "segunda_proposta_v055_real.json"


class DiagnosticValidationTests(unittest.TestCase):
    def setUp(self):
        self.real = json.loads(FIXTURE.read_text())

    def test_real_second_proposal_has_explicit_ether5_state_contradiction(self):
        errors = explicit_state_errors(self.real["proposta"], self.real)
        self.assertTrue(
            any(
                e["interface"] == "ether5"
                and e["metrica"] == "oper_status"
                and e["valor_texto"] == 1
                and e["valor_SNMP"] == 2
                for e in errors
            )
        )

    def test_real_free_next_steps_are_outside_program_catalog(self):
        install_verification_catalog(self.real)
        errors = verification_errors(self.real["proposta"], self.real)
        self.assertEqual(errors[0]["tipo"], "verificacao_fora_do_catalogo")

    def test_correct_explicit_state_is_accepted(self):
        d = {"resumo": "ether5 com oper_status=2 e admin_status=1."}
        self.assertEqual(explicit_state_errors(d, self.real), [])

    def test_ether1_and_ether2_states_are_not_transferred_between_ports(self):
        d = {"resumo": "ether1: admin_status=2."}
        self.assertEqual(explicit_state_errors(d, self.real)[0]["valor_SNMP"], 1)

    def test_explicit_future_or_conditional_state_is_not_current_assertion(self):
        for text in (
            "Se oper_status=1 em ether5, verificar o parceiro.",
            "Apos habilitacao, ether5 com oper_status=1 seria um resultado possivel.",
        ):
            self.assertEqual(explicit_state_errors({"resumo": text}, self.real), [])

    def test_explicit_negation_is_not_assertion_of_false_state(self):
        self.assertEqual(
            explicit_state_errors({"resumo": "ether5 nao tem oper_status=1."}, self.real), []
        )

    def test_ambiguous_multiport_sentence_is_not_assigned_by_guess(self):
        self.assertEqual(
            explicit_state_errors({"resumo": "ether1 e ether5 com oper_status=1."}, self.real), []
        )

    def test_checker_does_not_claim_to_audit_general_natural_language(self):
        self.assertEqual(
            explicit_state_errors(
                {"resumo": "A porta ether5 esta com cabo defeituoso."}, self.real
            ),
            [],
        )

    def test_only_selected_catalog_ids_can_be_proposed(self):
        p = packet()
        p["problemas_observados"] = [
            {"id": "D0", "codigo": "x", "proxima_verificacao": "Repetir coleta."}
        ]
        install_verification_catalog(p)
        for selected in ([], ["show dhcp"], ["V9"], ["V0", "V0"]):
            self.assertTrue(verification_errors({"proximas_verificacoes": selected}, p))
        self.assertEqual(verification_errors({"proximas_verificacoes": ["V0"]}, p), [])

    def test_schema_exposes_ids_and_program_owned_descriptions(self):
        p = packet()
        p["problemas_observados"] = [{"id": "D0", "proxima_verificacao": "Repetir coleta SNMP."}]
        install_verification_catalog(p)
        s = proposal_schema(p)["properties"]["proximas_verificacoes"]
        self.assertEqual(s["items"]["enum"], ["V0"])
        self.assertEqual(s["minItems"], 1)
        self.assertEqual(p["verificacoes_disponiveis"][0]["descricao"], "Repetir coleta SNMP.")

    def test_empty_catalog_requires_empty_selection(self):
        p = packet()
        p["problemas_observados"] = []
        install_verification_catalog(p)
        self.assertEqual(proposal_schema(p)["properties"]["proximas_verificacoes"]["maxItems"], 0)
        self.assertEqual(verification_errors({"proximas_verificacoes": []}, p), [])


class LocalGateTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(self, repair=False, execute=True):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            dev = Device()
            dev.data["ether5"].update(admin_status=2, oper_status=2)
            for state in dev.data.values():
                state["utc"] = utcnow()
            p = packet()
            p["problemas_observados"] = []
            p["objetivo_operador"] = {"tipo": "manter_estado_desejado"}
            p["evidencias"][0]["ferramenta"] = "consultar_cpu_memoria"
            bad = proposal()
            bad["problemas_identificados"] = []
            bad["limitacoes"] = ["Oper_status=1 em ether5 sem link e esperado e nao prova defeito."]
            good = copy.deepcopy(bad)
            good["limitacoes"] = ["ether5 com oper_status=2; causa fisica nao determinada."]

            class Agent(FakeAgent):
                def __init__(self, *a):
                    super().__init__(*a)
                    self.calls = []

                async def chat(self, messages, **kwargs):
                    self.calls.append(copy.deepcopy(messages))
                    return {"content": json.dumps(good if repair and len(self.calls) > 1 else bad)}

            class Reviewer:
                def __init__(self):
                    self.calls = 0

                async def review(self, p, doc, pid, ids):
                    self.calls += 1
                    r = opinion(pid, action=doc["acao"])
                    r.update(avaliacao_factual="sem_erro_identificado", erros_factuais=[])
                    return {"status": "concluida", "parecer": r, "contingencia_elegivel": False}

            agent = Agent(root / "r.json", bad)
            rev = Reviewer()
            prompts = []
            with contextlib.redirect_stdout(io.StringIO()):
                r = await supervise(
                    agent,
                    dev,
                    dev if execute else None,
                    p,
                    copy.deepcopy(dev.data),
                    rev,
                    execute,
                    True,
                    root,
                    {"tentativas": 0},
                    ask=lambda q: prompts.append(q) or "s",
                    pause=0,
                )
            return r, dev, rev, prompts, agent.calls

    async def test_local_contradiction_blocks_api_consent_and_set(self):
        r, dev, rev, prompts, calls = await self.scenario()
        self.assertEqual(r["resultado"], "bloqueado_validacao_local")
        self.assertEqual(dev.writes, [])
        self.assertEqual(rev.calls, 0)
        self.assertEqual(prompts, [])
        self.assertEqual(len(calls), 2)

    async def test_local_reformulation_preserves_action_and_allows_existing_executor(self):
        r, dev, rev, prompts, calls = await self.scenario(repair=True)
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertEqual(dev.writes, [6])
        self.assertEqual(rev.calls, 1)
        self.assertEqual(len(prompts), 1)
        self.assertIn("critica_python", calls[1][-1]["content"])
        self.assertEqual(r["rodadas"][1]["origem_feedback"], "python")

    async def test_simulation_stays_without_consent_or_write_after_local_repair(self):
        r, dev, rev, prompts, calls = await self.scenario(repair=True, execute=False)
        self.assertEqual(r["resultado"], "simulacao_proposta_revisada")
        self.assertEqual(dev.writes, [])
        self.assertEqual(prompts, [])
        self.assertEqual(rev.calls, 1)


if __name__ == "__main__":
    unittest.main()
