import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contexto_supervisionado import references
from monitoramento_continuo import IncidentTracker, load_profile, write_hold_status
from revisor_gpt import GPTReviewer, review_schema, validate_review
import test_monitoramento_continuo as continuous

FIXTURE = Path(__file__).resolve().parent.parent / "casos/adiamento_revisor_v058_real.json"


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tick = [1000]
        self.path = self.root / "incidents.json"
        self.tracker = IncidentTracker(self.path, load_profile(), clock=lambda: self.tick[0])
        self.signals = {"interface:ether1": "admin=2;oper=2"}
        self.tracker.observe(self.signals)

    def test_waits_until_actual_global_cooldown_end_not_general_600s(self):
        self.tick[0] = 1060
        self.tracker.complete(list(self.signals), "intervalo_SET_300s", retry_at=1300)
        self.tick[0] = 1299
        self.assertEqual(self.tracker.observe(self.signals), [])
        self.assertEqual(self.tracker.waiting()[0]["restante_s"], 1)
        self.tick[0] = 1300
        self.assertEqual(self.tracker.observe(self.signals), list(self.signals))

    def test_deadline_survives_restart_without_resetting_incident(self):
        self.tracker.complete(list(self.signals), "intervalo_SET_300s", retry_at=1300)
        old_id = self.tracker.entries["interface:ether1"]["id"]
        self.tick[0] = 1300
        other = IncidentTracker(self.path, load_profile(), clock=lambda: self.tick[0])
        self.assertEqual(other.observe(self.signals), list(self.signals))
        self.assertEqual(other.entries["interface:ether1"]["id"], old_id)

    def test_real_old_control_uses_300s_compatibility_without_deleting_state(self):
        record = json.loads(FIXTURE.read_text(encoding="utf-8"))[0]["monitoramento"]
        self.path.write_text(
            json.dumps(
                {"versao": 1, "perfil": record["perfil"], "incidentes": record["incidentes"]}
            )
        )
        item = record["incidentes"]["interface:ether1"]
        self.tick[0] = item["analise_epoch"] + 300
        tracker = IncidentTracker(self.path, record["perfil"], clock=lambda: self.tick[0])
        self.assertIn("interface:ether1", tracker.observe(record["sinais"]))
        self.assertEqual(tracker.entries["interface:ether1"]["id"], item["id"])

    def test_api_pending_still_uses_general_reanalysis_interval(self):
        self.tracker.complete(list(self.signals), "pendente_revisao_gpt")
        self.tick[0] = 1599
        self.assertEqual(self.tracker.observe(self.signals), [])
        self.tick[0] = 1600
        self.assertEqual(self.tracker.observe(self.signals), list(self.signals))

    def test_refusal_and_rejection_are_not_reopened_by_optional_deadline(self):
        for result in (
            "cancelado_operador",
            "revisao_rejeitar",
            "resultado_indeterminado_apos_SET",
        ):
            self.tracker.observe({})
            self.tracker.observe(self.signals)
            self.tracker.complete(list(self.signals), result, retry_at=0)
            self.tick[0] += 10000
            self.assertEqual(self.tracker.observe(self.signals), [])
            self.assertIsNone(self.tracker.waiting()[0]["proxima_analise_epoch"])

    def test_write_status_returns_real_deadline_and_keeps_limits(self):
        control = self.root / "controle/ultima_tentativa_ether5.json"
        control.parent.mkdir()
        control.write_text(json.dumps({"epoch": 1000}))
        session = {"tentativas": 1, "limite": 10}
        self.assertEqual(write_hold_status(self.root, session, 1299), ("intervalo_SET_300s", 1300))
        self.assertEqual(write_hold_status(self.root, session, 1300), (None, None))
        self.assertEqual(
            write_hold_status(self.root, {"tentativas": 10, "limite": 10}, 1300),
            ("limite_SET_sessao", None),
        )


class ReviewerIdentityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.real = json.loads(FIXTURE.read_text(encoding="utf-8"))[1]

    def test_real_id_was_truncated_and_is_not_silently_repaired(self):
        r = self.real
        self.assertEqual(len(r["proposta_id"]), 64)
        self.assertEqual(len(r["revisao_original"]["proposta_id"]), 63)
        with self.assertRaisesRegex(ValueError, "nao corresponde"):
            validate_review(
                r["revisao_original"],
                r["proposta_id"],
                references(r["contexto"]),
                r["proposta"]["acao"],
                factual_required=True,
            )
        schema = review_schema(
            references(r["contexto"]), r["proposta"]["acao"], True, r["proposta_id"]
        )
        self.assertEqual(schema["properties"]["proposta_id"]["enum"], [r["proposta_id"]])

    async def test_actual_request_binds_exact_id_and_keeps_rejection(self):
        r = self.real
        seen = []

        def transport(payload, *_):
            seen.append(payload)
            response = copy.deepcopy(r["revisao_original"])

            response["proposta_id"] = payload["text"]["format"]["schema"]["properties"][
                "proposta_id"
            ]["enum"][0]
            return {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(response)}],
                    }
                ],
            }

        result = await GPTReviewer("synthetic", transport=transport).review(
            r["contexto"], r["proposta"], r["proposta_id"], references(r["contexto"])
        )
        self.assertEqual(result["status"], "concluida")
        self.assertEqual(result["parecer"]["decisao"], "rejeitar")
        self.assertEqual(
            seen[0]["text"]["format"]["schema"]["properties"]["proposta_id"]["enum"],
            [r["proposta_id"]],
        )

    async def test_transport_ignoring_schema_still_blocked_with_specific_reason(self):
        r = self.real

        def transport(*_):
            return {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": json.dumps(r["revisao_original"])}
                        ],
                    }
                ],
            }

        result = await GPTReviewer("synthetic", transport=transport).review(
            r["contexto"], r["proposta"], r["proposta_id"], references(r["contexto"])
        )
        self.assertEqual(result["status"], "resposta_invalida")
        self.assertEqual(result["motivo_resposta_invalida"], "Revisao nao corresponde a proposta")
        self.assertIsNone(result["parecer"])
        self.assertFalse(result["contingencia_elegivel"])
        self.assertEqual(len(result["tentativas"]), 1)


class ContinuousCooldownTests(unittest.IsolatedAsyncioTestCase):
    async def test_bench_then_wan_resumes_after_cooldown_without_restart_and_with_new_consent(self):
        helper = continuous.ContinuousIntegrationTests()
        self.addCleanup(helper.doCleanups)
        tick = [1000]
        real_tracker = IncidentTracker

        def factory(path, profile, **kwargs):
            return real_tracker(path, profile, clock=lambda: tick[0], **kwargs)

        def before_cycle(index, dev, folder):
            tick[0] = (1000, 1060, 1299, 1300)[index]
            if index == 1:
                dev.data["ether1"].update(admin_status=2, oper_status=2)

        with (
            patch("monitoramento_continuo.time.time", side_effect=lambda: tick[0]),
            patch.object(continuous, "IncidentTracker", side_effect=factory),
        ):
            result = await helper.scenario(disabled=["ether5"], cycles=4, before_cycle=before_cycle)
        self.assertEqual(
            [r["resultado"] for r in result.results],
            [
                "habilitacao_confirmada",
                "intervalo_SET_300s",
                "monitoramento_sem_nova_analise",
                "habilitacao_confirmada",
            ],
        )
        self.assertEqual(result.dev.writes, [6, 2])
        self.assertEqual(len(result.prompts), 2)
        held = next(
            d for d in result.docs if d.get("status_execucao") == "monitoramento_sem_nova_analise"
        )
        waiting = held["monitoramento"]["adiamentos"][0]
        self.assertEqual(waiting["resultado_anterior"], "intervalo_SET_300s")
        self.assertEqual(waiting["restante_s"], 1)


if __name__ == "__main__":
    unittest.main()
