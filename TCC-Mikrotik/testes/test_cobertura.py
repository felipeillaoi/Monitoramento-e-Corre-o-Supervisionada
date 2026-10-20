import asyncio
import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agente_ia import Agent, MAX_COVERAGE_CALLS, now, run_cycles
from politica_diagnostico import assess, load_context
from test_agente_ia import FakeModel


def readings(old_port=True):
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    return [
        {
            "id": "E0",
            "utc": now(),
            "ferramenta": "consultar_cpu_memoria",
            "dados": {"tem_dados": True, "cpu_media_pct": 0, "memoria_pct": 23},
        },
        {
            "id": "E1",
            "utc": now(),
            "ferramenta": "consultar_interface",
            "dados": {"tem_dados": True, "nome": "ether1", "oper_status": 1},
        },
        {
            "id": "E2",
            "utc": old if old_port else now(),
            "ferramenta": "consultar_interface",
            "dados": {"tem_dados": True, "nome": "ether2", "oper_status": 1},
        },
    ]


class CoverageTools:
    def __init__(self, absent=False, failure=False, wrong_name=False):
        self.calls = []
        self.absent, self.failure, self.wrong_name = absent, failure, wrong_name

    def clean(self, value):
        return value

    async def execute(self, name, args):
        self.calls.append((name, dict(args)))
        if self.failure:
            return {"tem_dados": False, "erro": "Timeout simulado"}, []
        if name == "consultar_cpu_memoria":
            data = {"tem_dados": True, "cpu_media_pct": 0, "memoria_pct": 23}
        elif name == "listar_interfaces":
            data = {
                "tem_dados": True,
                "interfaces_max16": [
                    {"ifindex": 42, "nome": "ether1"},
                    {"ifindex": 91, "nome": "outra" if self.absent else "ether2"},
                ],
            }
        elif name == "consultar_interface":
            data = {
                "tem_dados": True,
                "nome": (
                    "renomeada"
                    if self.wrong_name
                    else "ether1"
                    if args["ifindex"] == 42
                    else "ether2"
                ),
                "oper_status": 1,
            }
        else:
            raise AssertionError("Ferramenta inesperada: " + name)
        return data, []


class CoverageTests(unittest.IsolatedAsyncioTestCase):
    async def run_coverage(self, evidence, tools=None, config=None):
        tools = tools or CoverageTools()
        with tempfile.TemporaryDirectory() as temp:
            agent = Agent(FakeModel(), tools, Path(temp) / "audit.json", config)
            agent.record["ferramentas"] = copy.deepcopy(evidence)
            await agent.complete_coverage(evidence)
            saved = json.loads((Path(temp) / "audit.json").read_text())
        return agent, tools, saved

    async def test_stale_ether2_is_refreshed_using_discovered_index(self):
        ev = readings()
        agent, tools, saved = await self.run_coverage(ev)
        self.assertEqual(
            tools.calls, [("listar_interfaces", {}), ("consultar_interface", {"ifindex": 91})]
        )
        self.assertEqual(assess(ev, agent.context, now())["classificacao"], "sem_anomalia_evidente")
        self.assertEqual(saved["cobertura_obrigatoria"]["pendencias_antes"], ["interface:ether2"])
        self.assertEqual(saved["cobertura_obrigatoria"]["pendencias_depois"], [])
        self.assertEqual(
            [e["origem"] for e in saved["ferramentas"][3:]], ["programa_cobertura"] * 2
        )
        self.assertEqual([e["id"] for e in saved["ferramentas"]], ["E0", "E1", "E2", "E3", "E4"])

    async def test_no_additional_queries_when_required_readings_are_fresh(self):
        _, tools, saved = await self.run_coverage(readings(False))
        self.assertEqual(tools.calls, [])
        self.assertEqual(saved["cobertura_obrigatoria"]["chamadas"], 0)

    async def test_unresolved_name_does_not_guess_index(self):
        ev = readings()
        agent, tools, saved = await self.run_coverage(ev, CoverageTools(absent=True))
        self.assertEqual(tools.calls, [("listar_interfaces", {})])
        self.assertEqual(saved["cobertura_obrigatoria"]["interfaces_nao_resolvidas"], ["ether2"])
        self.assertEqual(assess(ev, agent.context, now())["classificacao"], "inconclusivo")

    async def test_snmp_failure_remains_inconclusive_without_unbounded_retry(self):
        ev = []
        agent, tools, saved = await self.run_coverage(ev, CoverageTools(failure=True))
        self.assertEqual(len(tools.calls), 2)
        self.assertEqual(assess(ev, agent.context, now())["classificacao"], "inconclusivo")
        self.assertEqual(len(saved["cobertura_obrigatoria"]["pendencias_depois"]), 4)

    async def test_name_change_does_not_fill_wrong_port(self):
        ev = readings()
        agent, _, saved = await self.run_coverage(ev, CoverageTools(wrong_name=True))
        self.assertIn("interface:ether2", saved["cobertura_obrigatoria"]["pendencias_depois"])
        self.assertEqual(assess(ev, agent.context, now())["classificacao"], "inconclusivo")

    async def test_empty_history_gets_required_readings_with_bounded_budget(self):
        ev = []
        agent, tools, saved = await self.run_coverage(ev)
        self.assertEqual(len(tools.calls), MAX_COVERAGE_CALLS)
        self.assertEqual(assess(ev, agent.context, now())["classificacao"], "sem_anomalia_evidente")
        self.assertEqual(saved["cobertura_obrigatoria"]["pendencias_depois"], [])

    async def test_extra_required_ports_cannot_exceed_budget(self):
        config = load_context()
        config["interfaces_com_link_esperado"] += ["ether3", "ether4", "ether5"]
        ev = []
        _, tools, saved = await self.run_coverage(ev, config=config)
        self.assertEqual(len(tools.calls), MAX_COVERAGE_CALLS)
        self.assertEqual(len(saved["cobertura_obrigatoria"]["pendencias_depois"]), 3)


class CycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_serial_cycles_and_no_sleep_after_last(self):
        args = SimpleNamespace(ciclos=3, intervalo=60)
        events = []

        async def run(args, *_):
            events.append(("run", args.ciclo_atual))

        async def wait(seconds):
            events.append(("wait", seconds))

        with (
            patch("agente_ia.run_agent", side_effect=run),
            patch("agente_ia.asyncio.sleep", side_effect=wait),
        ):
            await run_cycles(args, object(), "secret1", "secret2")
        self.assertEqual(events, [("run", 1), ("wait", 60), ("run", 2), ("wait", 60), ("run", 3)])

    async def test_interrupt_stops_remaining_cycles(self):
        args = SimpleNamespace(ciclos=3, intervalo=60)
        with (
            patch("agente_ia.run_agent", side_effect=asyncio.CancelledError) as run,
            patch("agente_ia.asyncio.sleep", new_callable=AsyncMock) as wait,
        ):
            with self.assertRaises(asyncio.CancelledError):
                await run_cycles(args, object(), "secret1", "secret2")
        self.assertEqual(run.call_count, 1)
        wait.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
