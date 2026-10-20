import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from test_avaliacao_isolada import Model


class ModelSelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_diagnostic_evaluator_passes_selected_model_without_changing_case(self):
        import avaliar_diagnostico as evaluator

        model_name = "candidato-local"
        base = Model()
        backend = SimpleNamespace(metadata={"modelo": model_name}, preflight=Mock())

        async def chat(messages, **kwargs):
            return await base.chat(messages, **kwargs)

        backend.chat = chat
        cases = [copy.deepcopy(evaluator.make_cases()[0])]
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(evaluator, "BASE", Path(folder)),
                patch.object(evaluator, "make_cases", return_value=cases),
                patch("agente_ia.LocalOllama", return_value=backend) as factory,
            ):
                result = await evaluator.evaluate(
                    SimpleNamespace(ollama=True, cego=True, modelo=model_name)
                )
            factory.assert_called_once_with(model_name)
            summary = json.loads(next(Path(folder).rglob("resumo.json")).read_text())
            self.assertEqual(summary["modelo"]["modelo"], model_name)
            self.assertEqual(summary["casos"][0]["esperado"], cases[0]["esperado"])
            self.assertEqual(result, 0)

    async def test_logs_evaluator_passes_selected_model_and_keeps_expected_events(self):
        import avaliar_logs as evaluator

        case = copy.deepcopy(evaluator.make_cases()[0])
        model_name = "candidato-local"
        backend = SimpleNamespace(
            metadata={"modelo": model_name},
            preflight=Mock(),
            chat=AsyncMock(
                return_value={"message": {"content": json.dumps({"avaliacoes": case["esperado"]})}}
            ),
        )
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(evaluator, "BASE", Path(folder)),
                patch.object(evaluator, "make_cases", return_value=[case]),
                patch("agente_ia.LocalOllama", return_value=backend) as factory,
            ):
                result = await evaluator.evaluate(
                    SimpleNamespace(ollama=True, repeticoes=1, modelo=model_name)
                )
            factory.assert_called_once_with(model_name)
            summary = json.loads(next(Path(folder).rglob("resumo.json")).read_text())
            self.assertEqual(summary["modelo_solicitado"], model_name)
            self.assertTrue(summary["casos"][0]["modelo_ok"])
            self.assertEqual(result, 0)
