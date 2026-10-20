import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agente_ia import Agent, AgentError, EvidenceTools, LocalOllama, validate_report
from avaliar_diagnostico import make_cases
from politica_diagnostico import assess, load_context
from preparacao_diagnostico import model_context, expected_metric_states, audit_report
from test_agente_ia import valid_report


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.config = load_context()
        self.cases = {c["nome"]: c for c in make_cases()}

    def objective(self, name):
        case = self.cases[name]
        return assess(case["evidencias"], self.config, case["referencia"])

    def test_latest_null_does_not_fall_back_to_old_cpu(self):
        context = model_context(self.objective("cpu_ausente"), self.config, False)
        rows = {r["metrica"]: r for r in context["leituras_selecionadas"]}
        self.assertIsNone(rows["cpu_pct"]["valor"])
        self.assertEqual(rows["cpu_pct"]["evidencia"], "E1")
        self.assertGreater(rows["ram_pct"]["valor"], 0)

    def test_absent_port_has_explicit_row_and_nonrequired_ports_are_not_observations(self):
        context = model_context(self.objective("ether2_sem_dados"), self.config, False)
        rows = {r["metrica"]: r for r in context["leituras_selecionadas"]}
        self.assertEqual(set(rows), {"cpu_pct", "ram_pct", "interface:ether1", "interface:ether2"})
        self.assertIsNone(rows["interface:ether2"]["valor"])
        self.assertIsNone(rows["interface:ether2"]["evidencia"])
        self.assertNotIn("bridge", json.dumps(context))

    def test_manual_metric_labels_for_six_previous_blind_failures(self):
        expected = {
            "ether1_sem_link": ("interface:ether1", "alerta"),
            "cpu_ausente": ("cpu_pct", "ausente"),
            "ether2_sem_dados": ("interface:ether2", "ausente"),
            "todos_dados_antigos": ("cpu_pct", "antigo"),
            "relogio_anterior_as_leituras": ("cpu_pct", "tempo_inconsistente"),
            "cpu_fora_da_faixa": ("cpu_pct", "invalido"),
        }
        for name, (key, label) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    expected_metric_states(self.objective(name), self.config)[key], label
                )

    def test_temporal_and_value_boundaries(self):
        base = self.objective("normal_real")
        for value, age, expected in [
            (0, 0, "normal"),
            (85, 120, "alerta"),
            (100, 120.001, "antigo"),
            (150, 0, "invalido"),
            (True, 0, "invalido"),
            (0, -0.001, "tempo_inconsistente"),
        ]:
            with self.subTest(value=value, age=age):
                obj = copy.deepcopy(base)
                cpu = next(f for f in obj["fatos"] if f["metrica"] == "cpu_pct")
                cpu.update(valor=value, idade_s=age)
                self.assertEqual(expected_metric_states(obj, self.config)["cpu_pct"], expected)

    def test_semantic_errors_are_recorded_without_overwriting_proposal(self):
        objective = self.objective("ether1_sem_link")
        report = valid_report()
        saved = copy.deepcopy(report)
        result = audit_report(report, objective, self.config)
        self.assertEqual(result["acertos"], 3)
        self.assertEqual(report, saved)
        self.assertTrue(result["coerencia_interna_classificacao"])
        report["classificacao"] = "suspeita"
        self.assertFalse(
            audit_report(report, objective, self.config)["coerencia_interna_classificacao"]
        )

    def test_new_field_is_required_and_labels_are_validated(self):
        for kind in ("missing_field", "missing_metric", "unknown_label"):
            report = valid_report()
            if kind == "missing_field":
                del report["avaliacao_metricas"]
            elif kind == "missing_metric":
                del report["avaliacao_metricas"]["ram_pct"]
            else:
                report["avaliacao_metricas"]["ram_pct"] = "saudavel"
            with self.subTest(kind=kind), self.assertRaises(AgentError):
                validate_report(report, [{"id": "E1"}], self.config)


class BlindPayloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_case_payloads_fit_guard_and_do_not_contain_raw_history_or_answers(self):
        with tempfile.TemporaryDirectory() as temp:
            for case in make_cases():
                backend = LocalOllama()
                tools = EvidenceTools(
                    SimpleNamespace(host="192.168.88.1"), Path(temp) / "unused.db"
                )
                agent = Agent(backend, tools, Path(temp) / "audit.json")
                response = {
                    "done": True,
                    "done_reason": "stop",
                    "message": {"content": json.dumps(valid_report())},
                }
                with patch.object(backend, "request", return_value=response) as request:
                    proposal = await agent.build_report(
                        "Replay.", case["evidencias"], case["referencia"], include_policy=False
                    )
                self.assertEqual(request.call_count, 1)
                self.assertEqual(proposal, valid_report())
                payload = request.call_args.args[1]
                user = payload["messages"][1]["content"]
                for field in (
                    "perfil_python_fornecido",
                    "utilizavel",
                    "contadores_acumulados",
                    "cpu_indices_pct",
                    '"serie"',
                ):
                    self.assertNotIn(field, user)
                self.assertNotIn(case["nome"], user)
                self.assertEqual(
                    len(agent.record["contexto_enviado_ao_modelo"]["leituras_selecionadas"]), 4
                )


if __name__ == "__main__":
    unittest.main()
