import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from agente_ia import Agent, EvidenceTools
from politica_diagnostico import load_context
from avaliar_diagnostico import make_cases
from avaliacao_isolada import metric_messages, classify_metrics
from analise_logs import analyze
from test_agente_ia import valid_report


class Model:
    metadata = {"modelo": "simulado"}

    def __init__(self, state="normal"):
        self.state = state
        self.inputs = []

    async def chat(self, messages, schema=None):
        self.inputs.append((messages, schema))
        if "estado" in schema["properties"]:
            raw = {"estado": self.state}
        else:
            raw = valid_report("E0")
            raw["avaliacao_metricas"] = {key: self.state for key in raw["avaliacao_metricas"]}
            raw["classificacao"] = "suspeita" if self.state == "alerta" else "sem_anomalia_evidente"
        return {"message": {"content": json.dumps(raw)}}


class IsolatedTests(unittest.IsolatedAsyncioTestCase):
    def test_single_metric_keeps_full_numeric_age_without_other_metrics_or_labels(self):
        row = {"metrica": "interface:ether1", "valor": 1.0, "idade_da_leitura_segundos": 16.163}
        payload = metric_messages(row, {"idade_maxima_segundos": 120})
        data = json.loads(payload[1]["content"])
        self.assertEqual(data["idade_leitura_s"], 16.163)
        self.assertEqual(data["idade_maxima_s"], 120)
        self.assertNotIn("ether2", json.dumps(payload))
        self.assertNotIn("perfil_python", json.dumps(payload))
        self.assertNotIn("estado", data)

    async def test_blind_report_preserves_wrong_model_labels_without_truth_leakage(self):
        with tempfile.TemporaryDirectory() as folder:
            model = Model("alerta")
            tools = EvidenceTools(SimpleNamespace(host="192.168.88.1"), Path(folder) / "unused.db")
            config = load_context()
            config["avaliacao_isolada"] = True
            agent = Agent(model, tools, Path(folder) / "analise.json", config)
            case = make_cases()[0]
            report = await agent.build_report(
                "Logs nao devem entrar na redacao",
                case["evidencias"],
                case["referencia"],
                include_policy=False,
            )
            self.assertEqual(len(model.inputs), 5)
            self.assertEqual(report["avaliacao_metricas"]["interface:ether1"], "alerta")
            self.assertEqual(agent.record["auditoria_metricas_modelo"]["acertos"], 0)
            for messages, _ in model.inputs:
                self.assertNotIn("perfil_python_fornecido", json.dumps(messages))
            for _, schema in model.inputs[:4]:
                self.assertEqual(len(schema["properties"]["estado"]["enum"]), 6)
            self.assertEqual(
                model.inputs[-1][1]["properties"]["avaliacao_metricas"]["properties"]["cpu_pct"][
                    "enum"
                ],
                ["alerta"],
            )
            self.assertNotIn("eventos_arquivados", agent.record["contexto_enviado_ao_modelo"])
            self.assertEqual(
                agent.record["avaliacoes_individuais_metricas"][0]["proposta_original"],
                {"estado": "alerta"},
            )

    async def test_invalid_individual_reply_is_preserved_and_not_repaired(self):
        agent = SimpleNamespace(
            record={},
            save=Mock(),
            chat=AsyncMock(return_value={"content": '{"estado":"saudavel"}'}),
        )
        context = {
            "criterios": {"idade_maxima_segundos": 120, "limiar_cpu_pct": 85},
            "leituras_selecionadas": [
                {"metrica": "cpu_pct", "valor": 1, "idade_da_leitura_segundos": 1}
            ],
        }
        with self.assertRaises(ValueError):
            await classify_metrics(agent, context)
        self.assertEqual(agent.chat.call_count, 1)
        self.assertIn(
            "saudavel", agent.record["avaliacoes_individuais_metricas"][0]["conteudo_original"]
        )

    async def test_log_events_are_separate_and_wrong_temporal_label_is_not_replaced(self):
        ev = [
            {
                "id": "E3",
                "ferramenta": "consultar_logs_arquivados",
                "dados": {
                    "registros": [
                        {
                            "referencia": "LOG-1",
                            "router_time": "2026-10-13 15:44:14",
                            "topics": "interface;info",
                            "message": "ether1 link up",
                        },
                        {
                            "referencia": "LOG-2",
                            "router_time": "2026-10-13 15:41:59",
                            "topics": "interface;info",
                            "message": "ether1 link down",
                        },
                    ]
                },
            }
        ]
        inputs = []

        async def reply(messages, schema):
            context = json.loads(messages[1]["content"])
            inputs.append(context)
            event = context["eventos"][0]
            return {
                "content": json.dumps(
                    {
                        "avaliacoes": [
                            {
                                "chave": event["chave"],
                                "tipo_evento": "link_up_registrado"
                                if "up" in event["message"]
                                else "link_down_registrado",
                                "interface": "ether1",
                                "temporalidade": "recente",
                                "causa_fisica": "nao_determinada",
                            }
                        ]
                    }
                )
            }

        agent = SimpleNamespace(
            record={}, context={"avaliacao_isolada": True}, save=Mock(), chat=reply
        )
        result = await analyze(agent, ev, "2026-10-13T18:51:20+00:00", "-03:00")
        self.assertEqual(len(inputs), 2)
        self.assertTrue(all(len(c["eventos"]) == 1 for c in inputs))
        self.assertTrue(all("tipo_evento" not in c["eventos"][0] for c in inputs))
        self.assertEqual(result["resultado"], "divergente_no_escopo")
        self.assertEqual(
            result["proposta_original_modelo"]["avaliacoes"][0]["temporalidade"], "recente"
        )
        self.assertEqual(result["fatos_python"][0]["temporalidade"], "historico")

    async def test_event_reply_cannot_reference_a_different_individual_call(self):
        ev = [
            {
                "id": "E3",
                "ferramenta": "consultar_logs_arquivados",
                "dados": {
                    "registros": [
                        {
                            "referencia": "LOG-1",
                            "router_time": "2026-10-13 15:44:14",
                            "topics": "interface;info",
                            "message": "ether1 link up",
                        }
                    ]
                },
            }
        ]
        agent = SimpleNamespace(
            record={},
            context={"avaliacao_isolada": True},
            save=Mock(),
            chat=AsyncMock(return_value={"content": '{"avaliacoes":[{"chave":"E3/LOG-2"}]}'}),
        )
        result = await analyze(agent, ev, "2026-10-13T18:51:20+00:00", "-03:00")
        self.assertEqual(result["resultado"], "inconclusivo")
        self.assertIn("LOG-2", result["chamadas_individuais"][0]["conteudo_original"])


if __name__ == "__main__":
    unittest.main()
