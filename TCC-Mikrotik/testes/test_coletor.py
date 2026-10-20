import sqlite3
import tempfile
import unittest
from pathlib import Path

from coletor_snmp import (
    Collector,
    CPU,
    FIELDS,
    IFNAME,
    MEM,
    MEM_INDEX,
    RAM_TYPE,
    UPTIME,
    SnmpFailure,
    memory_values,
    open_database,
    traffic_rates,
)


def snapshot(**changes):
    data = dict(
        tempo=10.0,
        uptime=1000,
        rx_octetos=1000,
        tx_octetos=2000,
        descontinuidade=0,
        ultima_mudanca=0,
        nome="ether2",
        mac="mac1",
        oper_status=1,
    )
    data.update(changes)
    return data


class Calculations(unittest.TestCase):
    def test_memory_allocation_not_bytes(self):
        self.assertEqual(memory_values(1024, 262144, 59392), (268435456, 60817408, 22.65625))
        self.assertIsNone(memory_values(None, 100, 10))
        self.assertIsNone(memory_values(1024, 100, 101))

    def test_rates_exact_counter64(self):
        start = 2**63 + 10
        old = snapshot(rx_octetos=start, tx_octetos=start)
        new = snapshot(
            tempo=20, uptime=2000, rx_octetos=start + 1250000, tx_octetos=start + 2500000
        )
        self.assertEqual(traffic_rates(old, new, 30), (1.0, 2.0, "ok"))

    def test_initial_missing_reset_and_discontinuity(self):
        self.assertIsNone(traffic_rates(None, snapshot(), 30)[0])
        for changes in (
            {"uptime": 1},
            {"descontinuidade": 10},
            {"rx_octetos": 0},
            {"nome": "ether5"},
            {"ultima_mudanca": 2},
            {"tempo": 90},
            {"descontinuidade": None},
            {"oper_status": 2},
            {"nome": None},
        ):
            new = snapshot(tempo=20, uptime=2000, rx_octetos=5000, tx_octetos=5000)
            new.update(changes)
            self.assertIsNone(traffic_rates(snapshot(), new, 30)[0], changes)

    def test_missing_marker_allows_labeled_estimate(self):
        old = snapshot(descontinuidade=None)
        new = snapshot(
            tempo=20, uptime=2000, rx_octetos=1251000, tx_octetos=2502000, descontinuidade=None
        )
        self.assertEqual(traffic_rates(old, new, 30), (1.0, 2.0, "estimado_sem_marcador"))

    def test_fallback_still_rejects_resets_and_bad_samples(self):
        old = snapshot(descontinuidade=None)
        for changes in (
            {"uptime": 5},
            {"rx_octetos": 0},
            {"ultima_mudanca": 50},
            {"oper_status": 2},
            {"nome": "changed"},
            {"tempo": 90},
            {"rx_octetos": None},
            {"descontinuidade": 0},
        ):
            new = snapshot(
                tempo=20, uptime=2000, rx_octetos=1251000, tx_octetos=2502000, descontinuidade=None
            )
            new.update(changes)
            self.assertIsNone(traffic_rates(old, new, 30)[0], changes)


class FakeClient:
    host = "laboratorio-simulado"

    def __init__(self):
        self.fail = False
        self.missing_cpu = False
        self.missing_marker = False
        self.missing_rx = False
        self.ticks = 1000
        self.rx = 2**64 - 1

    async def walk(self, root, limit):
        if root == CPU:
            return {CPU + ".1": "10", CPU + ".2": "30"}
        return {IFNAME + ".3": "ether2"}

    async def get(self, oids):
        if self.fail:
            raise SnmpFailure("Timeout simulado")
        values = {
            UPTIME: str(self.ticks),
            f"{MEM}.2.{MEM_INDEX}": RAM_TYPE,
            f"{MEM}.4.{MEM_INDEX}": "1024",
            f"{MEM}.5.{MEM_INDEX}": "262144",
            f"{MEM}.6.{MEM_INDEX}": "59392",
            CPU + ".1": "10",
            CPU + ".2": None if self.missing_cpu else "30",
        }
        for name, (root, _) in FIELDS.items():
            values[root + ".3"] = str(
                {
                    "nome": "ether2",
                    "mac": "0x112233445566",
                    "oper_status": 1,
                    "admin_status": 1,
                    "rx_octetos": self.rx,
                    "tx_octetos": 5000,
                }.get(name, 0)
            )
        if self.missing_marker:
            values[FIELDS["descontinuidade"][0] + ".3"] = None
        if self.missing_rx:
            values[FIELDS["rx_octetos"][0] + ".3"] = None
        return {oid: values.get(oid) for oid in oids}


class Persistence(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "db.sqlite"
        self.db = open_database(self.path)
        self.client = FakeClient()
        self.collector = Collector(self.client, self.db, 10)
        await self.collector.discover()

    async def asyncTearDown(self):
        self.db.close()
        self.temp.cleanup()

    async def test_complete_persistence_and_large_counter(self):
        await self.collector.sample()
        self.assertEqual(self.db.execute("SELECT status FROM ciclos").fetchone()[0], "ok")
        self.assertEqual(
            self.db.execute(
                "SELECT valor FROM metricas WHERE metrica='cpu_media_indices_pct'"
            ).fetchone()[0],
            20,
        )
        self.assertEqual(
            self.db.execute("SELECT bruto FROM metricas WHERE metrica='rx_octetos'").fetchone()[0],
            str(2**64 - 1),
        )

        with sqlite3.connect(self.path) as other:
            self.assertEqual(other.execute("SELECT COUNT(*) FROM ciclos").fetchone()[0], 1)

    async def test_timeout_is_not_zero_and_resets_baseline(self):
        await self.collector.sample()
        self.client.fail = True
        await self.collector.sample()
        self.assertEqual(
            self.db.execute("SELECT status FROM ciclos ORDER BY id DESC").fetchone()[0], "falha"
        )
        self.assertEqual(
            self.db.execute(
                "SELECT COUNT(*) FROM metricas WHERE ciclo_id=2 AND valor IS NOT NULL"
            ).fetchone()[0],
            0,
        )
        self.assertFalse(self.collector.previous)

    async def test_partial_cpu_does_not_bias_average(self):
        self.client.missing_cpu = True
        await self.collector.sample()
        self.assertIsNone(
            self.db.execute(
                "SELECT valor FROM metricas WHERE metrica='cpu_media_indices_pct'"
            ).fetchone()[0]
        )
        self.assertEqual(self.db.execute("SELECT status FROM ciclos").fetchone()[0], "parcial")

    async def test_missing_marker_persists_limitation_and_rates(self):
        self.client.missing_marker = True
        self.client.rx = 1000
        await self.collector.sample()
        self.collector.previous[3]["tempo"] -= 10
        self.client.ticks = 2000
        self.client.rx += 1250000
        await self.collector.sample()
        statuses = self.db.execute("SELECT status FROM ciclos ORDER BY id").fetchall()
        self.assertEqual(statuses, [("ok_limitado",), ("ok_limitado",)])
        rate, quality = self.db.execute(
            "SELECT valor,status FROM metricas WHERE ciclo_id=2 AND metrica='rx_mbps'"
        ).fetchone()
        self.assertAlmostEqual(rate, 1.0, delta=0.01)
        self.assertEqual(quality, "estimado_sem_marcador")
        marker = self.db.execute(
            "SELECT bruto,valor,status FROM metricas WHERE ciclo_id=2 AND metrica='descontinuidade'"
        ).fetchone()
        self.assertEqual(marker, (None, None, "opcional_indisponivel"))

    async def test_missing_required_counter_remains_partial(self):
        self.client.missing_marker = self.client.missing_rx = True
        await self.collector.sample()
        self.assertEqual(self.db.execute("SELECT status FROM ciclos").fetchone()[0], "parcial")
        self.assertIsNone(
            self.db.execute("SELECT valor FROM metricas WHERE metrica='rx_mbps'").fetchone()[0]
        )


if __name__ == "__main__":
    unittest.main()
