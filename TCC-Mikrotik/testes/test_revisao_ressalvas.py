import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from revisor_gpt import GPTReviewer, InconsistentReview, validate_review
from supervisao import supervise
from test_supervisionado import FakeAgent, opinion, packet, proposal
from test_investigacao_interfaces import Device
from snmp_ether5 import utcnow


def actual_review():
    fixture = (
        Path(__file__).resolve().parent.parent
        / "casos"
        / "parecer_inconsistente_dados_faltantes.json"
    )
    return json.loads(fixture.read_text(encoding="utf-8"))["parecer"]


class ReviewCaveatTests(unittest.IsolatedAsyncioTestCase):
    def test_real_approval_with_missing_data_still_rejected(self):
        doc = actual_review()
        with self.assertRaisesRegex(InconsistentReview, "dados_faltantes preenchido"):
            validate_review(doc, doc["proposta_id"], doc["evidencias"], "habilitar_ether5")

    async def test_real_conflict_preserved_no_consent_no_set_no_fallback(self):
        original = actual_review()
        calls = []

        def transport(payload, key, timeout):
            calls.append(payload)

            incoming = json.loads(payload["input"][0]["content"])
            doc = dict(original, proposta_id=incoming["proposta_id"], evidencias=["E0", "I1"])
            return {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(doc)}],
                    }
                ],
            }

        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            dev = Device()
            dev.data["ether5"].update(admin_status=2, oper_status=2)
            for state in dev.data.values():
                state["utc"] = utcnow()
            agent = FakeAgent(folder / "r.json", proposal())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = await supervise(
                    agent,
                    dev,
                    dev,
                    packet(),
                    copy.deepcopy(dev.data),
                    GPTReviewer("synthetic-key", transport=transport),
                    True,
                    True,
                    folder,
                    {"tentativas": 0},
                    ask=lambda _: self.fail("Parecer inconsistente nao pode pedir consentimento"),
                    pause=0,
                )
            self.assertEqual(result["resultado"], "pendente_revisao_gpt")
            self.assertEqual(dev.writes, [])
            self.assertEqual(len(calls), 1)
            review = result["revisao_gpt"]
            self.assertFalse(review["contingencia_elegivel"])
            self.assertIsNone(review["parecer"])
            self.assertEqual(
                json.loads(review["conteudo_original"])["dados_faltantes"],
                original["dados_faltantes"],
            )
            self.assertIn("dados_faltantes preenchido", review["motivo_inconsistencia"])
            self.assertIn("Motivo do bloqueio:", output.getvalue())

    def test_nonblocking_caveats_in_reason_do_not_become_missing_data(self):
        doc = opinion("p")
        doc["justificativa"] = (
            "Restauracao administrativa no objetivo declarado. Link fisico e causa desconhecidos; GET posterior confirmara admin_status=1."
        )
        self.assertEqual(validate_review(doc, "p", ["E0", "I1"], "habilitar_ether5"), doc)

    def test_diagnostic_identifies_each_conflicting_field(self):
        doc = dict(
            opinion("p"),
            dados_faltantes=["Estado atual indispensavel ausente"],
            coerencia_acao_justificativa="inconclusiva",
            adequacao_objetivo="inadequada",
        )
        with self.assertRaises(InconsistentReview) as caught:
            validate_review(doc, "p", ["E0", "I1"], "habilitar_ether5")
        for field in ("dados_faltantes", "coerencia_acao_justificativa", "adequacao_objetivo"):
            self.assertIn(field, str(caught.exception))
