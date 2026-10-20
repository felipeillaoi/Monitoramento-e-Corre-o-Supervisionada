import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from analise_logs import catalogue, semantic_type, declared_offset, audit, analyze, audit_prose

REFERENCE = "2026-10-13T17:31:40+00:00"


def evidence(message="ether1 link down", time="2026-10-13 14:31:30", topics="interface;info"):
    return [
        {
            "id": "E3",
            "ferramenta": "consultar_logs_arquivados",
            "dados": {
                "ultima_coleta_utc": REFERENCE,
                "resultado_ultima_coleta": "snapshot_completo",
                "registros": [
                    {
                        "referencia": "LOG-139",
                        "message": message,
                        "router_time": time,
                        "topics": topics,
                    }
                ],
            },
        }
    ]


class LogTests(unittest.IsolatedAsyncioTestCase):
    def test_historical_event_remains_historical_despite_fresh_capture(self):
        ctx, expected = catalogue(evidence(time="2026-10-13 11:52:48"), REFERENCE, "-03:00")
        self.assertEqual(expected[0]["temporalidade"], "historico")
        self.assertEqual(ctx["eventos"][0]["idade_evento_s"], 9532)
        self.assertNotIn("tipo_evento", ctx["eventos"][0])

    def test_no_offset_does_not_invent_event_age(self):
        ctx, expected = catalogue(evidence(), REFERENCE)
        self.assertIsNone(ctx["eventos"][0]["idade_evento_s"])
        self.assertEqual(expected[0]["temporalidade"], "nao_comparavel")

    def test_boundary_future_and_partial_date(self):
        for date, status in (
            ("2026-10-13 14:29:40", "recente"),
            ("2026-10-13 14:29:39", "historico"),
            ("2026-10-13 14:31:41", "tempo_inconsistente"),
            ("14:31:30", "nao_comparavel"),
        ):
            with self.subTest(date=date):
                _, expected = catalogue(evidence(time=date), REFERENCE, "-03:00")
                self.assertEqual(expected[0]["temporalidade"], status)

    def test_explicit_administrative_change_and_no_physical_cause(self):
        _, expected = catalogue(
            evidence(
                "device changed by winbox:admin (/interface set ether1 disabled=yes)",
                topics="system;info",
            ),
            REFERENCE,
        )
        self.assertEqual(expected[0]["tipo_evento"], "desabilitacao_administrativa_registrada")
        self.assertEqual(expected[0]["causa_fisica"], "nao_determinada")

    def test_script_source_is_not_an_administrative_change(self):
        row = evidence(
            'new script added source="/interface set ether1 disabled=yes"', topics="system;info"
        )[0]["dados"]["registros"][0]
        self.assertEqual(semantic_type(row)[0], "outro")

    def test_no_guess_for_multiple_names_wrong_topic_and_ether10(self):
        for msg, topics in (
            ("ether10 link down", "interface;info"),
            ("ether1 link down", "system;info"),
            ("ether1 link down and ether2", "interface;info"),
        ):
            self.assertEqual(semantic_type({"message": msg, "topics": topics})[0], "outro")

    def test_audit_rejects_wrong_reference_type_age_cause_and_duplicates(self):
        _, expected = catalogue(evidence(), REFERENCE, "-03:00")
        self.assertTrue(audit({"avaliacoes": expected}, expected)["valido"])
        for key, value in (
            ("chave", "E8/LOG-139"),
            ("tipo_evento", "dhcp_registrado"),
            ("temporalidade", "historico"),
            ("causa_fisica", "cabo_ruim"),
        ):
            altered = copy.deepcopy(expected)
            altered[0][key] = value
            self.assertFalse(audit({"avaliacoes": altered}, expected)["valido"])
        self.assertFalse(audit({"avaliacoes": expected + expected}, expected)["valido"])

    def test_bounded_projection_original_unchanged(self):
        raw = evidence("x" * 1000)
        ctx, _ = catalogue(raw, REFERENCE)
        self.assertEqual(len(ctx["eventos"][0]["message"]), 220)
        self.assertTrue(ctx["eventos"][0]["trecho_truncado"])
        self.assertEqual(len(raw[0]["dados"]["registros"][0]["message"]), 1000)

    def test_offset_validation(self):
        for bad in ("America/Sao_Paulo", "-03:60", "+14:01", 3):
            with self.assertRaises(ValueError):
                declared_offset(bad)

    async def test_model_failure_preserves_facts_without_authorizing_action(self):
        agent = SimpleNamespace(
            record={"chamadas_modelo": [{}]},
            save=Mock(),
            chat=AsyncMock(side_effect=TimeoutError("modelo indisponivel")),
        )
        result = await analyze(agent, evidence(), REFERENCE)
        self.assertEqual(result["resultado"], "inconclusivo")
        self.assertEqual(len(result["fatos_python"]), 1)
        self.assertNotIn("acao", result)

    async def test_divergent_proposal_is_preserved_and_flagged(self):
        _, expected = catalogue(evidence(), REFERENCE)
        altered = copy.deepcopy(expected)
        altered[0]["temporalidade"] = "recente"
        agent = SimpleNamespace(
            record={"chamadas_modelo": [{}]},
            save=Mock(),
            chat=AsyncMock(return_value={"content": json.dumps({"avaliacoes": altered})}),
        )
        result = await analyze(agent, evidence(), REFERENCE)
        self.assertEqual(result["resultado"], "divergente_no_escopo")
        self.assertEqual(result["proposta_original_modelo"]["avaliacoes"], altered)

    def test_prose_audit_flags_missing_citation_without_claiming_full_validation(self):
        result = audit_prose(
            {"resumo": "Eventos recentes via Winbox", "evidencias": ["E1"]}, evidence()
        )
        self.assertEqual(len(result["alertas"]), 2)
        self.assertFalse(result["validacao_completa"])


if __name__ == "__main__":
    unittest.main()
