import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from monitoramento_continuo import IncidentTracker, load_profile
from politica_diagnostico import load_context
from snmp_ether5 import utcnow
import test_monitoramento_continuo as continuous

FIXTURE = Path(__file__).resolve().parent.parent / "casos/reincidencia_v059_real.json"


class RecurrenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "incidents.json"
        self.tick = [1000]
        self.profile = load_profile()
        self.context = load_context()
        self.tracker = IncidentTracker(self.path, self.profile, clock=lambda: self.tick[0])

    def snapshot(self, name="ether1", admin=1, oper=1):
        s = continuous.fresh_states()[name]
        s.update(admin_status=admin, oper_status=oper)
        return s

    def test_real_saved_success_no_longer_suppresses_current_disabled_wan(self):
        record = json.loads(FIXTURE.read_text(encoding="utf-8"))[0]["monitoramento"]
        self.path.write_text(
            json.dumps(
                {"versao": 1, "perfil": record["perfil"], "incidentes": record["incidentes"]}
            )
        )
        old_id = record["incidentes"]["interface:ether1"]["id"]
        self.tick[0] = record["incidentes"]["interface:ether5"]["analise_epoch"] + 1
        tracker = IncidentTracker(self.path, record["perfil"], clock=lambda: self.tick[0])
        due = tracker.observe(record["sinais"])
        self.assertEqual(due, ["interface:ether1"])
        self.assertNotEqual(tracker.entries["interface:ether1"]["id"], old_id)
        self.assertEqual(tracker.events[0]["motivo"], "desabilitada_apos_habilitacao_confirmada")
        self.assertEqual(tracker.entries["interface:ether5"]["resultado"], "intervalo_SET_300s")

    def test_post_get_closes_only_corrected_interface(self):
        self.tracker.observe(
            {
                "interface:ether1": "admin=2;oper=2",
                "interface:ether5": "admin=2;oper=opcional",
                "dhcp:wan": "cliente_marcado_invalido",
            }
        )
        other = copy.deepcopy(self.tracker.entries["interface:ether5"])
        self.tracker.complete(["interface:ether1"], "habilitacao_confirmada")
        event = self.tracker.reconcile_post_set(self.snapshot(), self.context, utcnow())
        self.assertEqual(event["evento"], "resolvido_por_GET_pos_SET")
        self.assertNotIn("interface:ether1", self.tracker.entries)
        self.assertEqual(self.tracker.entries["interface:ether5"], other)
        self.assertIn("dhcp:wan", self.tracker.entries)

    def test_immediate_disable_after_post_get_creates_new_episode_without_healthy_poll(self):
        signal = {"interface:ether1": "admin=2;oper=2"}
        self.tracker.observe(signal)
        old = self.tracker.entries["interface:ether1"]["id"]
        self.tracker.complete(list(signal), "habilitacao_confirmada")
        self.tracker.reconcile_post_set(self.snapshot(), self.context, utcnow())
        self.assertEqual(self.tracker.observe(signal), ["interface:ether1"])
        self.assertNotEqual(self.tracker.entries["interface:ether1"]["id"], old)

    def test_enabled_wan_without_link_remains_new_link_incident(self):
        self.tracker.observe({"interface:ether1": "admin=2;oper=2"})
        self.tracker.complete(["interface:ether1"], "habilitacao_confirmada")
        event = self.tracker.reconcile_post_set(self.snapshot(oper=2), self.context, utcnow())
        self.assertEqual(event["evento"], "novo_episodio_por_GET_pos_SET")
        entry = self.tracker.entries["interface:ether1"]
        self.assertEqual(entry["estado"], "admin=1;oper=2")
        self.assertIsNone(entry["resultado"])
        self.assertTrue(self.tracker.due("interface:ether1"))

    def test_ether5_enabled_without_link_resolves_administrative_incident(self):
        self.tracker.observe({"interface:ether5": "admin=2;oper=opcional"})
        event = self.tracker.reconcile_post_set(
            self.snapshot("ether5", oper=2), self.context, utcnow()
        )
        self.assertEqual(event["evento"], "resolvido_por_GET_pos_SET")
        self.assertNotIn("interface:ether5", self.tracker.entries)

    def test_stale_missing_future_or_still_disabled_snapshot_does_not_close_incident(self):
        self.tracker.observe({"interface:ether1": "admin=2;oper=2"})
        bad = [{}, None, self.snapshot(admin=2)]
        for seconds in (-121, 121):
            s = self.snapshot()
            s["utc"] = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
            bad.append(s)
        for snapshot in bad:
            with self.subTest(snapshot=snapshot):
                self.assertIsNone(self.tracker.reconcile_post_set(snapshot, self.context, utcnow()))
                self.assertIn("interface:ether1", self.tracker.entries)

    def test_legacy_refusal_or_rejection_is_not_a_recurrence(self):
        signal = {"interface:ether1": "admin=2;oper=2"}
        for result in (
            "cancelado_operador",
            "revisao_rejeitar",
            "resultado_indeterminado_apos_SET",
        ):
            self.tracker.observe({})
            self.tracker.observe(signal)
            self.tracker.complete(list(signal), result)
            self.tick[0] += 10000
            self.assertEqual(self.tracker.observe(signal), [])

    def test_successful_get_closure_survives_restart(self):
        self.tracker.observe({"interface:ether1": "admin=2;oper=2"})
        self.tracker.reconcile_post_set(self.snapshot(), self.context, utcnow())
        reloaded = IncidentTracker(self.path, self.profile, clock=lambda: self.tick[0])
        self.assertEqual(reloaded.entries, {})
        self.assertEqual(
            reloaded.observe({"interface:ether1": "admin=2;oper=2"}), ["interface:ether1"]
        )


class ContinuousRecurrenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_wan_recurrence_with_bench_disabled_prioritizes_wan_and_requires_new_consent(
        self,
    ):
        helper = continuous.ContinuousIntegrationTests()
        self.addCleanup(helper.doCleanups)
        tick = [1000]
        real_tracker = IncidentTracker

        def factory(path, profile, **kwargs):
            return real_tracker(path, profile, clock=lambda: tick[0], **kwargs)

        def before_cycle(index, dev, folder):
            tick[0] = (1000, 1060, 1300, 1360, 1600)[index]
            if index == 1:
                dev.data["ether1"].update(admin_status=2, oper_status=2)
                dev.data["ether5"].update(admin_status=2, oper_status=2)

        with (
            patch("monitoramento_continuo.time.time", side_effect=lambda: tick[0]),
            patch.object(continuous, "IncidentTracker", side_effect=factory),
        ):
            result = await helper.scenario(disabled=["ether1"], cycles=5, before_cycle=before_cycle)
        self.assertEqual(result.dev.writes, [2, 2, 6])
        self.assertEqual(len(result.prompts), 3)
        self.assertEqual(
            [r["resultado"] for r in result.results],
            [
                "habilitacao_confirmada",
                "intervalo_SET_300s",
                "habilitacao_confirmada",
                "intervalo_SET_300s",
                "habilitacao_confirmada",
            ],
        )
        self.assertEqual(result.tracker.entries, {})
        self.assertTrue(
            any(
                d.get("monitoramento", {}).get("reconciliacao_pos_SET", {}).get("evento")
                == "resolvido_por_GET_pos_SET"
                for d in result.docs
            )
        )


if __name__ == "__main__":
    unittest.main()
