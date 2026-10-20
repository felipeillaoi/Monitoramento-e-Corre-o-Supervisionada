import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from agente_ia import Agent, AgentError


class Tools:
    logs_enabled = True

    def __init__(self):
        self.calls = []

    def clean(self, value):
        return value

    async def execute(self, name, args):
        self.calls.append((name, args))
        when = datetime.now(timezone.utc).isoformat()
        if name == "ler_historico":
            return {
                "tem_dados": True,
                "serie": [{"utc": when, "cpu_pct": 1, "ram_pct": 25}],
                "interfaces_ultimo_ciclo_max16": [
                    {"nome": name, "oper_status": 1} for name in ("ether1", "ether2")
                ],
            }, []
        if name == "consultar_logs_arquivados":
            return {
                "tem_dados": True,
                "ultima_coleta_utc": when,
                "resultado_ultima_coleta": "snapshot_completo",
                "registros": [
                    {
                        "referencia": "LOG-1",
                        "router_time": "2026-10-13 11:00:00",
                        "topics": "interface;info",
                        "message": "ether1 link down",
                    }
                ],
            }, []
        raise AssertionError("Consulta inesperada: " + name)


class Model:
    metadata = {"modelo": "simulado"}

    def __init__(self, fail_logs=False):
        self.fail_logs = fail_logs

    async def chat(self, messages, schema=None, tools=None):
        if schema and "estado" in schema["properties"]:
            return {"message": {"content": '{"estado":"normal"}'}}
        if schema and "avaliacoes" in schema["properties"]:
            if self.fail_logs:
                raise AgentError("Timeout simulado do modelo na interpretacao de logs")
            rows = [
                {
                    "chave": "E1/LOG-1",
                    "interface": "ether1",
                    "tipo_evento": "link_down_registrado",
                    "temporalidade": "nao_comparavel",
                    "causa_fisica": "nao_determinada",
                }
            ]
            return {"message": {"content": json.dumps({"avaliacoes": rows})}}
        if schema:
            report = {
                "avaliacao_metricas": {
                    "cpu_pct": "normal",
                    "ram_pct": "normal",
                    "interface:ether1": "normal",
                    "interface:ether2": "normal",
                },
                "classificacao": "sem_anomalia_evidente",
                "resumo": "Metricas dentro do perfil observado.",
                "evidencias": ["E0"],
                "hipoteses": [],
                "limitacoes": [],
                "proximas_verificacoes": [],
            }
            return {"message": {"content": json.dumps(report)}}
        return {"message": {"content": "PRONTO"}}


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_individual_mode_completes_triage_and_separate_log_evaluation(self):
        with tempfile.TemporaryDirectory() as folder:
            agent = Agent(Model(), Tools(), Path(folder) / "analise.json")
            agent.context["avaliacao_isolada"] = True
            report = await agent.run("Analise a RB e os logs")
            self.assertEqual(report["classificacao"], "sem_anomalia_evidente")
            self.assertEqual(len(agent.record["avaliacoes_individuais_metricas"]), 4)
            self.assertEqual(agent.record["analise_logs_estruturada"]["modo_geracao"], "individual")
            self.assertNotIn("eventos_arquivados", agent.record["contexto_enviado_ao_modelo"])
            self.assertFalse(agent.record["classificacao_python_fornecida_ao_modelo"])
            self.assertEqual(agent.record["status_execucao"], "concluida")

    async def test_program_log_coverage_is_attributed_and_history_not_current_fault(self):
        with tempfile.TemporaryDirectory() as folder:
            tools = Tools()
            agent = Agent(Model(), tools, Path(folder) / "analise.json")
            report = await agent.run("Analise a RB")
            self.assertEqual(report["classificacao"], "sem_anomalia_evidente")
            self.assertEqual(agent.record["ferramentas"][1]["origem"], "programa_cobertura_logs")
            self.assertEqual(
                agent.record["analise_logs_estruturada"]["resultado"], "concordante_no_escopo"
            )
            self.assertEqual(agent.record["chamadas_modelo"][-1]["etapa"], "interpretacao_logs")
            self.assertEqual(len(tools.calls), 2)
            self.assertNotIn("atuacao_controlada", agent.record)

    async def test_log_model_failure_keeps_metric_triage_and_original_proposal(self):
        with tempfile.TemporaryDirectory() as folder:
            agent = Agent(Model(fail_logs=True), Tools(), Path(folder) / "analise.json")
            report = await agent.run("Analise a RB")
            self.assertEqual(report["classificacao"], "sem_anomalia_evidente")
            self.assertEqual(agent.record["status_execucao"], "concluida")
            self.assertEqual(agent.record["analise_logs_estruturada"]["resultado"], "inconclusivo")
            self.assertEqual(
                agent.record["proposta_original_modelo"]["classificacao"], "sem_anomalia_evidente"
            )
