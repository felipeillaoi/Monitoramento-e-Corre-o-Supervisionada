import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from avaliar_revisor_factual import cases
from fatos_diagnostico import compile_facts
from revisor_gpt import validate_review, validate_factual_quotes, InconsistentReview, GPTReviewer
from supervisao import supervise
from test_supervisionado import opinion, FakeAgent, packet, proposal
from test_investigacao_interfaces import Device
from snmp_ether5 import utcnow


def audit(pid="p", decision="aprovar", errors=None, action="investigar"):
    errors = errors or []
    result = opinion(pid, decision, action)
    result.update(
        evidencias=["E1", "I0"],
        avaliacao_factual="erros_identificados" if errors else "sem_erro_identificado",
        erros_factuais=errors,
    )
    return result


def error(quote="A ether1 esta sem link fisico."):
    return {
        "trecho": quote,
        "correcao": "I0 mostra ether1 com oper_status=1; o link esta up.",
        "evidencias": ["I0"],
    }


class FactTests(unittest.TestCase):
    def test_current_incident_distinguishes_link_from_disabled_dhcp(self):
        p = cases()[0]["packet"]
        facts = compile_facts(p)
        self.assertEqual(facts["interfaces"][0]["oper_status"], 1)
        self.assertTrue(facts["wan"]["dhcp"]["disabled"])
        self.assertIsNone(facts["wan"]["dhcp"]["invalid"])

    def test_route_and_dns_counts_keep_limited_scope(self):
        f = cases()[0]["packet"]["fatos_conferiveis"]
        self.assertEqual(f["wan"]["rotas_PADRAO_ipv4_MAIN_ativas"], 0)
        self.assertEqual(f["wan"]["dns_servers_e_dynamic_servers"], 0)
        self.assertNotIn("tabela_main_vazia", f["wan"])
        self.assertNotIn("dns_pc_falhou", f["wan"])

    def test_latest_failed_observation_does_not_reuse_previous_success(self):
        p = cases()[0]["packet"]
        p["evidencias"].append(
            {"id": "E2", "ferramenta": "consultar_estado_wan", "dados": {"tem_dados": False}}
        )
        self.assertFalse(compile_facts(p)["wan"]["tem_dados"])

    def test_stale_or_future_wan_and_interface_values_are_not_current_facts(self):
        for value in (121, -1):
            p = cases()[0]["packet"]
            p["evidencias"][0]["idade_consulta_s"] = value
            for row in p["interfaces"]:
                row["idade_s"] = value
            self.assertEqual(compile_facts(p)["interfaces"], [])
            self.assertFalse(compile_facts(p)["wan"]["tem_dados"])

    def test_collection_timestamp_cannot_be_missing(self):
        p = cases()[0]["packet"]
        del p["evidencias"][0]["dados"]["utc"]
        self.assertFalse(compile_facts(p)["wan"]["tem_dados"])

    def test_six_case_suite_has_one_control_and_five_targeted_contradictions(self):
        suite = cases()
        self.assertEqual(len(suite), 6)
        self.assertEqual([c["esperado"] for c in suite].count("aprovar"), 1)
        self.assertTrue(all(c["proposta"]["acao"] == "investigar" for c in suite))


class ReviewValidationTests(unittest.TestCase):
    def check(self, doc):
        return validate_review(doc, "p", ["E1", "I0"], "investigar", factual_required=True)

    def test_old_action_only_approval_cannot_satisfy_factual_review(self):
        with self.assertRaises(ValueError):
            self.check(opinion("p", action="investigar"))

    def test_coherent_action_does_not_override_reported_factual_error(self):
        with self.assertRaises(InconsistentReview):
            self.check(audit(errors=[error()]))

    def test_inconclusive_factual_assessment_cannot_approve(self):
        doc = audit()
        doc["avaliacao_factual"] = "inconclusiva"
        with self.assertRaises(InconsistentReview):
            self.check(doc)

    def test_error_rating_and_error_list_must_agree(self):
        for rating, errors in [("sem_erro_identificado", [error()]), ("erros_identificados", [])]:
            doc = audit("p", "rejeitar")
            doc.update(avaliacao_factual=rating, erros_factuais=errors)
            with self.assertRaises(InconsistentReview):
                self.check(doc)

    def test_cited_error_must_reference_existing_evidence(self):
        e = error()
        e["evidencias"] = ["INVENTADO"]
        with self.assertRaises(ValueError):
            self.check(audit("p", "rejeitar", [e]))

    def test_rejection_with_specific_supported_error_is_accepted(self):
        doc = audit("p", "rejeitar", [error()])
        self.assertEqual(self.check(doc)["decisao"], "rejeitar")

    def test_criticized_quote_must_exist_in_proposal(self):
        with self.assertRaises(InconsistentReview):
            validate_factual_quotes(audit("p", "rejeitar", [error()]), cases()[0]["proposta"])
        validate_factual_quotes(audit("p", "rejeitar", [error()]), cases()[1]["proposta"])

    def test_quotes_inside_problem_explanations_are_checked(self):
        p = cases()[0]["proposta"]
        e = error(p["problemas_identificados"][0]["explicacao"])
        validate_factual_quotes(audit("p", "rejeitar", [e]), p)


class APIReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_api_schema_requires_factual_review_for_expanded_packets(self):
        seen = []

        def transport(payload, *_):
            seen.append(payload)
            return {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(audit())}],
                    }
                ],
            }

        case = cases()[0]
        r = await GPTReviewer("test", transport=transport).review(
            case["packet"], case["proposta"], "p", ["E1", "I0"]
        )
        self.assertEqual(r["status"], "concluida")
        required = seen[0]["text"]["format"]["schema"]["required"]
        self.assertIn("avaliacao_factual", required)
        self.assertIn("erros_factuais", required)

    async def test_bad_approval_is_not_a_transient_outage_or_fallback(self):
        def transport(*_):
            return {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": json.dumps(audit(errors=[error()]))}
                        ],
                    }
                ],
            }

        case = cases()[1]
        r = await GPTReviewer("test", transport=transport).review(
            case["packet"], case["proposta"], "p", ["E1", "I0"]
        )
        self.assertEqual(r["status"], "parecer_inconsistente")
        self.assertFalse(r["contingencia_elegivel"])
        self.assertEqual(len(r["tentativas"]), 1)


class SupervisionTests(unittest.IsolatedAsyncioTestCase):
    async def test_reported_factual_error_blocks_write_despite_action_approval(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            dev = Device()
            dev.data["ether5"].update(admin_status=2, oper_status=2)
            for row in dev.data.values():
                row["utc"] = utcnow()
            p = packet()
            p["problemas_observados"] = []
            p["objetivo_operador"] = {"tipo": "manter_estado_desejado"}
            p["evidencias"][0]["ferramenta"] = "consultar_cpu_memoria"
            doc = proposal()
            doc["problemas_identificados"] = []
            agent = FakeAgent(root / "r.json", doc)

            class Reviewer:
                async def review(self, p, proposal, pid, ids):
                    result = opinion(pid, action=proposal["acao"])
                    result.update(
                        avaliacao_factual="erros_identificados",
                        erros_factuais=[
                            {
                                "trecho": proposal["resumo"],
                                "correcao": "Critica sintetica para testar bloqueio.",
                                "evidencias": ["I1"],
                            }
                        ],
                    )
                    return {
                        "status": "concluida",
                        "parecer": result,
                        "contingencia_elegivel": False,
                    }

            with contextlib.redirect_stdout(io.StringIO()):
                r = await supervise(
                    agent,
                    dev,
                    dev,
                    p,
                    copy.deepcopy(dev.data),
                    Reviewer(),
                    True,
                    True,
                    root,
                    {"tentativas": 0},
                    ask=lambda _: self.fail(
                        "Nao pode pedir consentimento para parecer inconsistente"
                    ),
                    pause=0,
                )
            self.assertEqual(r["resultado"], "bloqueado_erro")
            self.assertEqual(dev.writes, [])

    async def test_specific_factual_feedback_reaches_qwen_reformulation(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            p = cases()[0]["packet"]
            bad = cases()[1]["proposta"]
            good = cases()[0]["proposta"]

            class Agent(FakeAgent):
                calls = []

                async def chat(self, messages, **kwargs):
                    self.calls.append(copy.deepcopy(messages))
                    doc = copy.deepcopy(bad if len(self.calls) == 1 else good)
                    view = json.loads(messages[1]["content"])
                    if view.get("verificacoes_disponiveis"):
                        doc["proximas_verificacoes"] = [view["verificacoes_disponiveis"][0]["id"]]
                    return {"content": json.dumps(doc)}

            class Reviewer:
                count = 0

                async def review(self, p, doc, pid, ids):
                    self.count += 1
                    return {
                        "status": "concluida",
                        "parecer": audit(pid, "rejeitar", [error()])
                        if self.count == 1
                        else audit(pid),
                        "contingencia_elegivel": False,
                    }

            agent = Agent(root / "r.json", bad)
            reviewer = Reviewer()
            dev = Device()
            with contextlib.redirect_stdout(io.StringIO()):
                r = await supervise(
                    agent,
                    dev,
                    None,
                    p,
                    copy.deepcopy(dev.data),
                    reviewer,
                    False,
                    False,
                    root,
                    {"tentativas": 0},
                    pause=0,
                )
            self.assertEqual(r["resultado"], "sem_acao_executavel")
            self.assertEqual(reviewer.count, 2)
            self.assertIn("erros_factuais", agent.calls[1][-1]["content"])
            self.assertEqual(dev.writes, [])
            self.assertTrue(r["auditoria_factual_obrigatoria"])


if __name__ == "__main__":
    unittest.main()
