import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from avaliar_diagnostico import make_cases
from politica_diagnostico import assess, load_context, render_verified
from agente_ia import Agent, EvidenceTools, LocalOllama, model_context
from test_agente_ia import valid_report


class PolicyTests(unittest.TestCase):
    def test_blind_projection_excludes_verdict_alerts_and_derived_labels(self):
        case = make_cases()[0]
        config = load_context()
        objective = assess(case["evidencias"], config, case["referencia"])
        objective.update(
            classificacao="VEREDITO_SECRETO",
            alertas=["ALERTA_SECRETO"],
            pendencias=["PENDENCIA_SECRETA"],
            limitacoes=["LIMITACAO_SECRETA"],
        )
        for fact in objective["fatos"]:
            fact["utilizavel"] = "ROTULO_SECRETO"
        blind = model_context(objective, config, False)
        serialized = json.dumps(blind)
        for hidden in (
            "VEREDITO_SECRETO",
            "ALERTA_SECRETO",
            "PENDENCIA_SECRETA",
            "LIMITACAO_SECRETA",
            "ROTULO_SECRETO",
        ):
            self.assertNotIn(hidden, serialized)
        self.assertEqual(blind["criterios"]["idade_maxima_segundos"], config["idade_maxima_s"])
        self.assertEqual(len(blind["leituras_selecionadas"]), 4)
        self.assertIn("VEREDITO_SECRETO", json.dumps(model_context(objective, config, True)))

    def test_all_labelled_cases(self):
        config = load_context()
        for case in make_cases():
            with self.subTest(case=case["nome"]):
                result = assess(case["evidencias"], config, case["referencia"])
                self.assertEqual(result["classificacao"], case["esperado"])

    def test_real_case_times_and_scope(self):
        case = make_cases()[0]
        result = assess(case["evidencias"], load_context(), case["referencia"])
        self.assertEqual(result["historicos"][0]["idade_s"], 25.082)
        ages = {f["metrica"]: f["idade_s"] for f in result["fatos"]}
        self.assertEqual(ages["cpu_pct"], 12)
        self.assertEqual(ages["interface:ether1"], 9)
        self.assertFalse(result["alertas"])
        self.assertFalse(result["pendencias"])
        output = render_verified(result)
        self.assertEqual(output["origem"], "perfil_objetivo_python")
        self.assertIn("Isso nao e evidencia de reset", str(output["limitacoes"]))

    def test_metric_freshness_independent_of_other_live_readings(self):
        case = make_cases()[0]
        ev = case["evidencias"]
        ev[1]["utc"] = "2026-10-02T12:08:06+00:00"
        for row in ev[0]["dados"]["serie"]:
            row["utc"] = row["utc"].replace("2026-10-03", "2026-10-02")
        result = assess(ev, load_context(), case["referencia"])
        self.assertIn("cpu_pct", result["pendencias"])
        self.assertIn("ram_pct", result["pendencias"])
        self.assertTrue(
            next(f for f in result["fatos"] if f["metrica"] == "interface:ether1")["utilizavel"]
        )
        self.assertEqual(result["classificacao"], "inconclusivo")

    def test_expectations_are_configurable_not_unconditional_port_exception(self):
        case = make_cases()[0]
        config = load_context()
        config["interfaces_com_link_esperado"].append("ether3")
        result = assess(case["evidencias"], config, case["referencia"])
        self.assertEqual(result["classificacao"], "suspeita")
        self.assertEqual(result["alertas"][0]["metrica"], "interface:ether3")


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_blind_evaluator_does_not_send_case_name_or_expected_label(self):
        import avaliar_diagnostico as evaluator

        case = make_cases()[0]
        case["nome"] = "nome_secreto_do_caso"
        case["esperado"] = "GABARITO_NAO_ENVIAR"
        proposal = valid_report()

        def reply(route, payload):
            raw = (
                {"estado": "normal"}
                if "estado" in payload.get("format", {}).get("properties", {})
                else proposal
            )
            return {"done": True, "done_reason": "stop", "message": {"content": json.dumps(raw)}}

        with tempfile.TemporaryDirectory() as temp:
            backend = LocalOllama()
            with (
                patch.object(evaluator, "BASE", Path(temp)),
                patch.object(evaluator, "make_cases", return_value=[case]),
                patch("agente_ia.LocalOllama", return_value=backend),
                patch.object(backend, "preflight", return_value={}),
                patch.object(backend, "request", side_effect=reply) as request,
            ):
                await evaluator.evaluate(SimpleNamespace(ollama=True, cego=True))
            self.assertEqual(request.call_count, 5)
            sent = json.dumps([call.args[1] for call in request.call_args_list], ensure_ascii=False)
            self.assertNotIn("GABARITO_NAO_ENVIAR", sent)
            self.assertNotIn("nome_secreto_do_caso", sent)
            self.assertNotIn('"avaliacao_objetiva"', sent)
            self.assertNotIn('"utilizavel"', sent)
            self.assertIn("idade_da_leitura_segundos", sent)
            self.assertNotIn("perfil_python_fornecido", sent)
            self.assertNotIn("cpu_indices_pct", sent)
            summary_path = next(Path(temp).rglob("resumo.json"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["modo"], "replay_ollama_cego")
            self.assertFalse(summary["classificacao_python_fornecida_ao_modelo"])
            self.assertIn("acerto_classificacao_modelo_cego", summary["casos"][0])

    async def test_prompt_for_real_fixture_fits_guard_and_preserves_model_proposal(self):
        case = make_cases()[0]
        proposal = valid_report()
        proposal.update(classificacao="suspeita", resumo="Proposta propositalmente divergente.")
        with tempfile.TemporaryDirectory() as temp:
            backend = LocalOllama()
            toolset = EvidenceTools(SimpleNamespace(host="192.168.88.1"), Path(temp) / "unused.db")
            agent = Agent(backend, toolset, Path(temp) / "audit.json")
            with patch.object(
                backend,
                "request",
                return_value={
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 2500,
                    "message": {"content": json.dumps(proposal)},
                },
            ) as request:
                result = await agent.build_report("Analise", case["evidencias"], case["referencia"])
            self.assertEqual(result, proposal)
            self.assertEqual(request.call_count, 1)
            self.assertEqual(
                agent.record["avaliacao_objetiva_enviada_ao_modelo"]["classificacao"],
                "sem_anomalia_evidente",
            )
            self.assertEqual(
                json.loads(agent.record["tentativas_relatorio"][0]["conteudo_original"]), proposal
            )
            self.assertFalse((Path(temp) / "unused.db").exists())
            self.assertFalse(
                agent.record["auditoria_metricas_modelo"]["coerencia_interna_classificacao"]
            )


if __name__ == "__main__":
    unittest.main()
