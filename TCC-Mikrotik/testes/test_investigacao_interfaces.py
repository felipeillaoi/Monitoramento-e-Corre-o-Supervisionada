import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, AsyncMock, patch

from investigacao_interfaces import (
    PORTS,
    run_interfaces,
    expected_action,
    pending_ports,
    port_messages,
)


def states():
    return {
        name: {
            "utc": "2026-10-13T14:00:00+00:00",
            "ifindex": idx,
            "descricao": "RouterOS RB750Gr3",
            "uptime_ticks": 1000,
            "nome": name,
            "tipo": 6,
            "mac": PORTS[name]["mac"],
            "admin_status": 1,
            "oper_status": 2 if name == "ether5" else 1,
        }
        for name, idx in (("ether1", 2), ("ether2", 3), ("ether5", 6))
    }


class Device:
    def __init__(self, data=None):
        self.data = copy.deepcopy(data or states())
        self.investigated, self.writes = [], []
        self.response = {"resultado": "aceito", "detalhe": "noError"}
        self.effect = True
        self.fail_post = False

    async def inventory(self):
        return copy.deepcopy(self.data)

    async def investigate(self, name):
        self.investigated.append(name)
        return {
            "estado_inicial": copy.deepcopy(self.data[name]),
            "estado_final": copy.deepcopy(self.data[name]),
            "contadores_iniciais": {},
            "contadores_finais": {},
            "deltas": {},
        }

    async def find_ports(self):
        return {name: s["ifindex"] for name, s in self.data.items()}

    async def snapshot(self, idx):
        if self.writes and self.fail_post:
            raise TimeoutError()
        return copy.deepcopy(next(s for s in self.data.values() if s["ifindex"] == idx))

    async def enable(self, idx):
        self.writes.append(idx)
        if self.effect:
            s = next(s for s in self.data.values() if s["ifindex"] == idx)
            s["admin_status"] = 1
            s["oper_status"] = 1 if PORTS[s["nome"]]["link_esperado"] else 2
        return self.response


class ModelAgent:
    def __init__(self, path, requests=None, wrong_action=None, on_plan=None, wrong_ref=False):
        self.log_path = path
        self.record = {}
        self.requests = list(requests or [])
        self.wrong_action = wrong_action
        self.on_plan = on_plan
        self.wrong_ref = wrong_ref

    def save(self):
        self.log_path.write_text(json.dumps(self.record), encoding="utf-8")

    async def chat(self, messages, **kwargs):
        if "tools" in kwargs:
            if self.requests:
                name = self.requests.pop(0)
                return {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "investigar_interface",
                                "arguments": {"interface": name},
                            }
                        }
                    ]
                }
            return {"content": "PRONTO"}
        data = json.loads(messages[1]["content"])
        name = data["interface"]
        row = {
            "admin_status_lido": data["admin_status"],
            "oper_status_lido": data["oper_status"],
            "evidencia": "I0" if self.wrong_ref else data["evidencia"],
            "acao": self.wrong_action.get(
                name, expected_action({"nome": name, "ifindex": 1, **data})
            )
            if self.wrong_action
            else expected_action({"nome": name, "ifindex": 1, **data}),
        }
        if self.on_plan:
            callback, self.on_plan = self.on_plan, None
            callback()
        return {"content": json.dumps(row)}


class InvestigationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    async def run_case(
        self,
        device=None,
        requests=None,
        execute=True,
        wrong_action=None,
        on_plan=None,
        wrong_ref=False,
        session=None,
    ):
        d = device or Device()
        a = ModelAgent(self.folder / "analise.json", requests, wrong_action, on_plan, wrong_ref)
        r = await run_interfaces(
            a,
            d,
            d if execute else None,
            execute,
            self.folder / "atuacao",
            session or {"tentativas": 0},
            pause=0,
        )
        return r, d, a

    async def test_normal_no_action(self):
        r, d, _ = await self.run_case()
        self.assertEqual(r["resultado"], "sem_correcao_administrativa_indicada")
        self.assertEqual(d.writes, [])

    async def test_wan_disabled_investigated_and_enabled(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data), ["ether1"])
        self.assertEqual(d.investigated, ["ether1"])
        self.assertEqual(d.writes, [2])
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertTrue(r["link_esperado_recuperado"])
        events = [e["evento"] for e in r["eventos"]]
        self.assertLess(events.index("investigacao_SNMP"), events.index("SET_a_enviar"))

    async def test_ether5_no_cable_can_be_enabled(self):
        data = states()
        data["ether5"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data), ["ether5"])
        self.assertEqual(d.writes, [6])
        self.assertEqual(r["estado_final"]["oper_status"], 2)

    async def test_simulation_has_no_set(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data), ["ether1"], execute=False)
        self.assertEqual(r["resultado"], "simulacao_habilitacao_proposta_sem_SET")
        self.assertEqual(d.writes, [])

    async def test_physical_link_down_not_enabled_again(self):
        data = states()
        data["ether1"]["oper_status"] = 2
        r, d, _ = await self.run_case(Device(data), ["ether1"])
        self.assertEqual(d.writes, [])
        finding = next(f for f in r["achados_python"] if f["interface"] == "ether1")
        self.assertIn("link_esperado_nao_ativo", finding["indicadores"])
        self.assertEqual(r["resultado"], "sem_correcao_administrativa_indicada")

    async def test_protected_management_never_enabled(self):
        data = states()
        data["ether2"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(
            Device(data), ["ether2"], wrong_action={"ether2": "habilitar_interface"}
        )
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")
        self.assertEqual(d.writes, [])

    async def test_no_investigation_no_enable(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data))
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")
        self.assertEqual(d.writes, [])

    async def test_wrong_reference_blocks(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data), ["ether1"], wrong_ref=True)
        self.assertEqual(d.writes, [])
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")

    async def test_state_change_before_set_cancels(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        d = Device(data)
        r, d, _ = await self.run_case(
            d, ["ether1"], on_plan=lambda: d.data["ether1"].update(admin_status=1)
        )
        self.assertEqual(r["resultado"], "cancelado_estado_mudou_antes_SET")
        self.assertEqual(d.writes, [])

    async def test_wrong_mac_blocks(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2, mac="00:00:00:00:00:00")
        r, d, _ = await self.run_case(Device(data), ["ether1"])
        self.assertEqual(d.writes, [])

    async def test_unknown_interface_request_blocks(self):
        r, d, _ = await self.run_case(requests=["ether3"])
        self.assertEqual(d.investigated, [])
        self.assertEqual(d.writes, [])

    async def test_only_one_candidate_is_executed(self):
        data = states()
        for name in ("ether1", "ether5"):
            data[name].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data), ["ether5", "ether1"])
        self.assertEqual(d.writes, [2])
        self.assertEqual(r["candidatas_nao_executadas"], ["ether5"])

    async def test_lost_reply_does_not_claim_confirmed_set(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        d = Device(data)
        d.response = {"resultado": "indeterminado", "detalhe": "timeout"}
        r, d, _ = await self.run_case(d, ["ether1"])
        self.assertEqual(r["resultado"], "habilitada_sem_confirmacao_SET")
        self.assertEqual(d.writes, [2])

    async def test_post_read_timeout_not_success(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        d = Device(data)
        d.fail_post = True
        r, d, _ = await self.run_case(d, ["ether1"])
        self.assertEqual(r["resultado"], "resultado_indeterminado")

    async def test_main_routes_new_mode_with_separate_credentials(self):
        from agente_ia import run_agent, Agent, fallback
        from politica_diagnostico import load_context

        for execute in (False, True):
            with self.subTest(execute=execute):
                args = SimpleNamespace(
                    host="192.168.88.1",
                    usuario="tcc-monitor",
                    banco=self.folder / "db",
                    context=load_context(),
                    pergunta="Teste",
                    cenario_ether5=False,
                    cenario_interfaces=True,
                    executar_correcoes=execute,
                    credenciais_escrita=("write-auth", "write-privacy"),
                    sessao_atuacao={"tentativas": 0},
                )
                legacy = Mock(connect=AsyncMock(), close=Mock())
                transports = []

                def factory(*credentials):
                    c = Mock(connect=AsyncMock(), close=Mock())
                    transports.append((credentials, c))
                    return c

                result = {
                    "resultado": "sem_correcao_administrativa_indicada",
                    "eventos": [],
                    "registro_atuacao": str(self.folder / "interfaces.json"),
                }
                with (
                    patch("agente_ia.BASE", self.folder),
                    patch("agente_ia.Client", return_value=legacy),
                    patch.object(Agent, "run", new=AsyncMock(return_value=fallback("teste"))),
                    patch("investigacao_interfaces.Client", side_effect=factory),
                    patch(
                        "investigacao_interfaces.run_interfaces", new=AsyncMock(return_value=result)
                    ) as phase,
                ):
                    await run_agent(args, SimpleNamespace(metadata={}), "read-auth", "read-privacy")
                    self.assertEqual(transports[0][0], ("tcc-monitor", "read-auth", "read-privacy"))
                    self.assertEqual(len(transports), 2 if execute else 1)
                    self.assertIs(phase.call_args.args[3], execute)
                    if execute:
                        self.assertEqual(
                            transports[1][0], ("tcc-escrita", "write-auth", "write-privacy")
                        )
                    else:
                        self.assertIsNone(phase.call_args.args[2])
                    for _, c in transports:
                        c.close.assert_called_once()

    def test_pending_ports_do_not_confuse_unused_port_with_fault(self):
        data = states()
        self.assertEqual(pending_ports(data), [])
        data["ether1"].update(admin_status=2, oper_status=2)
        self.assertEqual(pending_ports(data), ["ether1"])

    async def test_unrelated_port_query_is_blocked(self):
        data = states()
        data["ether1"].update(admin_status=2, oper_status=2)
        r, d, _ = await self.run_case(Device(data), ["ether2"])
        self.assertEqual(d.investigated, [])
        self.assertEqual(d.writes, [])
        self.assertEqual(r["resultado"], "bloqueado_ou_inconclusivo")

    def test_port_prompt_uses_actual_reference(self):
        prompt = port_messages("ether1", states()["ether1"], "I3")
        self.assertNotIn('"A0"', prompt[0]["content"])
        self.assertIn('"I3"', prompt[0]["content"])
