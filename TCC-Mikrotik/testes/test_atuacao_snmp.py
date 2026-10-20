import copy
import unittest
from unittest.mock import AsyncMock, patch
from pysnmp.proto.rfc1902 import Integer, OctetString, TimeTicks, ObjectName
from pysnmp.smi.view import MibViewController
from teste_atuacao_snmp import (
    exercise,
    TestFailure,
    MAC,
    Client,
    ADMIN,
    DESC,
    UPTIME,
    IFDESCR,
    IFTYPE,
    IFMAC,
    OPER,
)

STATE = {
    "utc": "2026-10-11T17:00:00+00:00",
    "ifindex": 6,
    "descricao": "RouterOS RB750Gr3",
    "uptime_ticks": 1000,
    "nome": "ether5",
    "tipo": 6,
    "mac": MAC,
    "admin_status": 2,
    "oper_status": 2,
}


class MemoryJournal:
    def __init__(self, fail_intent=False):
        self.events = []
        self.fail_intent = fail_intent

    def add(self, event, **details):
        if self.fail_intent and event == "SET_a_enviar":
            raise OSError("Disco indisponivel")
        self.events.append((event, details))


class FakeClient:
    def __init__(self, states, reply=None):
        self.states = copy.deepcopy(states)
        self.reply = reply or {"resultado": "aceito", "detalhe": "noError"}
        self.writes = []

    async def discover(self):
        return 6

    async def snapshot(self, idx):
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if isinstance(state, Exception):
            raise state
        return state

    async def enable(self, idx):
        self.writes.append(idx)
        return self.reply


class TestActuation(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, client, enable=True, journal=None):
        return await exercise(client, journal or MemoryJournal(), enable, pause=0)

    async def test_read_only_never_writes(self):
        c = FakeClient([STATE])
        self.assertEqual(await self.invoke(c, False), "somente_leitura")
        self.assertEqual(c.writes, [])

    async def test_wrong_identity_blocks_write(self):
        for change in (
            {"nome": "ether2"},
            {"mac": "00:00:00:00:00:00"},
            {"tipo": 24},
            {"descricao": "Outro roteador"},
        ):
            c = FakeClient([STATE | change])
            with self.assertRaises(TestFailure):
                await self.invoke(c)
            self.assertEqual(c.writes, [])

    async def test_admin_up_oper_down_is_not_disabled(self):
        c = FakeClient([STATE | {"admin_status": 1}])
        self.assertEqual(await self.invoke(c), "ja_habilitada_sem_SET")
        self.assertEqual(c.writes, [])

    async def test_changed_precondition_blocks(self):
        c = FakeClient([STATE, STATE | {"admin_status": 1}])
        with self.assertRaises(TestFailure):
            await self.invoke(c)
        self.assertEqual(c.writes, [])

    async def test_no_write_without_audit(self):
        c = FakeClient([STATE])
        with self.assertRaises(OSError):
            await self.invoke(c, journal=MemoryJournal(fail_intent=True))
        self.assertEqual(c.writes, [])

    async def test_success_does_not_require_physical_link(self):
        c = FakeClient([STATE, STATE, STATE | {"admin_status": 1}])
        j = MemoryJournal()
        self.assertEqual(await self.invoke(c, journal=j), "habilitacao_confirmada")
        self.assertEqual(c.writes, [6])
        self.assertIn(
            ("SET_a_enviar", {"oid": "1.3.6.1.2.1.2.2.1.7.6", "tipo": "INTEGER", "valor": 1}),
            j.events,
        )

    async def test_rejection_does_not_retry(self):
        c = FakeClient([STATE], {"resultado": "recusado", "detalhe": "notWritable"})
        self.assertEqual(await self.invoke(c), "SET_recusado")
        self.assertEqual(c.writes, [6])

    async def test_lost_set_response_not_attributed_as_success(self):
        c = FakeClient(
            [STATE, STATE, STATE | {"admin_status": 1}],
            {"resultado": "indeterminado", "detalhe": "timeout"},
        )
        self.assertEqual(await self.invoke(c), "habilitada_sem_confirmacao_do_SET")
        self.assertEqual(c.writes, [6])

    async def test_ack_without_change_is_not_success(self):
        c = FakeClient([STATE])
        self.assertEqual(await self.invoke(c), "habilitacao_nao_confirmada")

    async def test_post_get_failure_is_unknown(self):
        c = FakeClient([STATE, STATE, TimeoutError()])
        self.assertEqual(await self.invoke(c), "resultado_indeterminado")
        self.assertEqual(c.writes, [6])

    async def test_reboot_blocks_success(self):
        c = FakeClient([STATE, STATE, STATE | {"admin_status": 1, "uptime_ticks": 1}])
        self.assertEqual(await self.invoke(c), "resultado_indeterminado")

    async def test_changed_target_after_set_blocks_success(self):
        c = FakeClient([STATE, STATE, STATE | {"admin_status": 1, "nome": "ether2"}])
        self.assertEqual(await self.invoke(c), "resultado_indeterminado")


class TestSnmpAdapter(unittest.IsolatedAsyncioTestCase):
    async def test_set_encodes_only_admin_up(self):
        client = Client("teste", "senha1234", "senha5678")
        response = (None, Integer(0), Integer(0), [(ObjectName(ADMIN + ".6"), Integer(1))])
        try:
            with patch(
                "teste_atuacao_snmp.set_cmd", new_callable=AsyncMock, return_value=response
            ) as call:
                self.assertEqual((await client.enable(6))["resultado"], "aceito")
                binding = call.call_args.args[4]
                binding.resolve_with_mib(MibViewController(client.engine.get_mib_builder()))
                self.assertEqual(str(binding[0].get_oid()), ADMIN + ".6")
                self.assertEqual(int(binding[1]), 1)
                self.assertEqual(binding[1].tagSet, Integer(1).tagSet)
                call.assert_awaited_once()
        finally:
            client.close()

    async def test_snapshot_decodes_routeros_octet_mac(self):
        client = Client("teste", "senha1234", "senha5678")
        values = {
            DESC: OctetString("RouterOS RB750Gr3"),
            UPTIME: TimeTicks(1000),
            IFDESCR + ".6": OctetString("ether5"),
            IFTYPE + ".6": Integer(6),
            IFMAC + ".6": OctetString(hexValue="D0EA110B47EA"),
            ADMIN + ".6": Integer(2),
            OPER + ".6": Integer(2),
        }
        response = (
            None,
            Integer(0),
            Integer(0),
            [(ObjectName(oid), value) for oid, value in values.items()],
        )
        try:
            with patch("teste_atuacao_snmp.get_cmd", new_callable=AsyncMock, return_value=response):
                state = await client.snapshot(6)
                self.assertEqual(state["mac"], MAC)
                self.assertEqual(state["admin_status"], 2)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
