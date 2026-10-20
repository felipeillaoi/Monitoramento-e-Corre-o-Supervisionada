import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, AsyncMock

from observacao_wan import (
    parse_snapshot,
    response_diagnostics,
    dhcp_flag,
    locate,
    SCRIPT,
    NAMES,
    EXECUTE,
    MARKER,
    WANObserver,
)
from diagnostico_ampliado import wan_signals, build_findings, SERVICE_KEYS
from monitoramento_continuo import load_profile, IncidentTracker
from politica_diagnostico import load_context
from snmp_ether5 import utcnow, DESC, UPTIME
from investigacao_interfaces import PORTS
from contexto_supervisionado import references
from supervisao import proposal_schema, validate_proposal, PROPOSAL_SYSTEM
import test_monitoramento_continuo as support
from test_supervisionado import packet, proposal
from agente_ia import dumps


def payload():
    return {
        "version": 1,
        "interface": "ether1",
        "mac": PORTS["ether1"]["mac"],
        "dhcp_count": 1,
        "dhcp": {
            "id": "*1",
            "disabled": False,
            "invalid": False,
            "status": "bound",
            "address": "192.168.0.121/24",
            "gateway": "192.168.0.1",
            "add_default_route": "yes",
        },
        "ipv4_count": 1,
        "default_routes": 1,
        "dns_servers": 2,
        "doh_configured": False,
        "free_hdd": 5242880,
        "total_hdd": 16777216,
        "errors": "",
    }


def sample(changes=None, client=None):
    d = payload()
    d.update(changes or {})
    if client:
        d["dhcp"].update(client)
    return parse_snapshot(MARKER + json.dumps(d))


def findings(wan=None, metrics=None, data=None):
    return build_findings(
        metrics
        or {"tem_dados": True, "cpu_media_pct": 1, "cpu_indices_pct": {"1": 1}, "memoria_pct": 24},
        data if data is not None else support.fresh_states(),
        load_context(),
        load_profile(),
        utcnow(),
        "E0",
        wan,
        "E1",
    )


class ProtocolTests(unittest.TestCase):
    def test_only_explicit_boolean_representations_are_normalized(self):
        for value in (True, "yes", "true"):
            self.assertIs(dhcp_flag(value, "disabled"), True)
        for value in (False, "no", "false"):
            self.assertIs(dhcp_flag(value, "disabled"), False)
        for value in (None, ""):
            self.assertIsNone(dhcp_flag(value, "invalid"))

    def test_unknown_flag_values_are_not_coerced_with_python_truthiness(self):
        for value in (0, 1, [], {}, "False", "0", "1", " yes ", "desconhecido"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dhcp_flag(value, "invalid")

    def test_explicit_text_flags_have_conversion_audit(self):
        w = sample(client={"disabled": "no", "invalid": "false"})
        self.assertIs(w["dhcp"]["disabled"], False)
        self.assertIs(w["dhcp"]["invalid"], False)
        self.assertEqual(w["qualidade"], "ok")
        self.assertEqual(
            w["normalizacao_flags_dhcp"], {"disabled": "str->bool", "invalid": "str->bool"}
        )

    def test_missing_flag_marks_partial_without_discarding_independent_fields(self):
        for value in (None, ""):
            w = sample(client={"invalid": value})
            self.assertTrue(w["tem_dados"])
            self.assertEqual(w["qualidade"], "parcial")
            self.assertIsNone(w["dhcp"]["invalid"])
            self.assertEqual(w["campos_indisponiveis"], ["dhcp.invalid"])
            self.assertEqual(w["free_hdd"], 5242880)
            self.assertEqual(w["default_routes"], 1)

    def test_diagnostic_flag_types_do_not_include_received_values(self):
        d = payload()
        d["dhcp"]["invalid"] = "segredo-teste"
        raw = MARKER + json.dumps(d)
        info = response_diagnostics(raw)
        self.assertEqual(info["tipos_flags_dhcp"], {"disabled": "bool", "invalid": "str"})
        self.assertNotIn("segredo-teste", json.dumps(info))

    def test_device_report_with_empty_optional_gateway_is_valid(self):
        w = sample({"dns_servers": 1, "free_hdd": 5246976}, client={"gateway": ""})
        self.assertEqual(w["dhcp"]["status"], "bound")
        self.assertEqual(wan_signals(w, utcnow()), {})

    def test_numeric_console_preamble_is_rejected_not_silently_removed(self):
        raw = "1\r\n1\r\n" + MARKER + json.dumps(payload())
        with self.assertRaisesRegex(ValueError, "Saida extra"):
            parse_snapshot(raw)
        self.assertEqual(response_diagnostics(raw)["posicao_marcador"], 6)

    def test_numeric_only_response_has_actionable_error(self):
        for raw in ("1", "1\r\n1\r\n"):
            with self.assertRaisesRegex(ValueError, "apenas contagem"):
                parse_snapshot(raw)

    def test_permissions_and_missing_marker_have_distinct_errors(self):
        with self.assertRaisesRegex(ValueError, "erro de permissao"):
            parse_snapshot("error: not enough permissions (9)")
        with self.assertRaisesRegex(ValueError, "Marcador.*ausente"):
            parse_snapshot("")

    def test_truncated_json_is_not_repaired(self):
        raw = MARKER + json.dumps(payload())[:-1]
        with self.assertRaisesRegex(ValueError, "JSON WAN invalido ou incompleto"):
            parse_snapshot(raw)
        self.assertFalse(response_diagnostics(raw)["termina_com_chave"])

    def test_diagnostics_include_structure_only(self):
        raw = "segredo-que-nao-deve-ser-arquivado\n" + MARKER + "{}"
        info = response_diagnostics(raw)
        self.assertNotIn("segredo", json.dumps(info))
        self.assertEqual(info["quantidade_marcadores"], 1)
        self.assertEqual(info["bytes_utf8"], len(raw.encode("utf-8")))

    def test_updater_targets_exactly_one_observer_without_changing_network(self):
        source = (
            Path(__file__).resolve().parent.parent
            / "routeros"
            / "atualizar_observacao_wan_v052.rsc"
        ).read_text()
        self.assertIn("[:len $tccObserver] != 1", source)
        self.assertIn(
            "/system script set $tccObserver policy=read dont-require-permissions=no", source
        )
        self.assertNotIn("count-only", source)
        self.assertEqual(source.count(":put ("), 1)
        self.assertNotIn("/system script remove", source)
        self.assertNotIn("/ip route add", source)
        self.assertIn("[:len [/ip address find where", source)
        self.assertIn("[:len [/ip route find where", source)

    def test_valid_snapshot(self):
        w = sample()
        self.assertTrue(w["tem_dados"])
        self.assertEqual(w["qualidade"], "ok")

    def test_permission_error_is_not_valid_snapshot(self):
        for raw in ("error: not enough permissions (9)", "", MARKER + "{}", MARKER + "[]"):
            with self.assertRaises(ValueError):
                parse_snapshot(raw)

    def test_reject_duplicate_json_keys_and_oversize(self):
        with self.assertRaises(ValueError):
            parse_snapshot(MARKER + '{"version":1,"version":1}')
        with self.assertRaises(ValueError):
            parse_snapshot(MARKER + "x" * 1801)

    def test_wrong_host_or_port_or_protocol(self):
        for values in (
            {"mac": "00:00:00:00:00:00"},
            {"mac": 1},
            {"interface": "ether2"},
            {"version": True},
            {"version": 2},
        ):
            with self.assertRaises(ValueError):
                sample(values)

    def test_counters_are_strict_nonnegative_or_unknown(self):
        for v in (True, 1.5, -2, 65536):
            with self.assertRaises(ValueError):
                sample({"dhcp_count": v})

    def test_flags_unknown_status_and_id_rejected(self):
        for values in (
            {"disabled": "False"},
            {"invalid": 0},
            {"status": "saudavel"},
            {"id": "1"},
            {"address": "not-an-ip"},
        ):
            with self.assertRaises(ValueError):
                sample(client=values)

    def test_bound_with_disabled_or_no_address_is_contradictory(self):
        for values in ({"disabled": True}, {"address": ""}, {"address": "0.0.0.0/0"}):
            with self.assertRaises(ValueError):
                sample(client=values)

    def test_missing_or_ambiguous_clients_do_not_select_arbitrary_detail(self):
        for count in (0, 2, -1):
            w = sample({"dhcp_count": count, "dhcp": ""})
            self.assertEqual(w["dhcp"], "")
            with self.assertRaises(ValueError):
                sample({"dhcp_count": count})

    def test_disk_bytes_not_percent_and_free_cannot_exceed_total(self):
        with self.assertRaises(ValueError):
            sample({"free_hdd": 999999999, "total_hdd": 1})
        with self.assertRaises(ValueError):
            sample({"free_hdd": True})

    def test_only_named_script_and_valid_suffix_can_be_executed(self):
        self.assertEqual(
            locate({NAMES + ".7": SCRIPT, NAMES + ".8": "another-script"}), EXECUTE + ".7"
        )
        for rows in (
            {},
            {NAMES + ".1": SCRIPT, NAMES + ".2": SCRIPT},
            {NAMES + ".0": SCRIPT},
            {NAMES + ".x": SCRIPT},
        ):
            with self.assertRaises(Exception):
                locate(rows)

    def test_partial_errors_preserve_unknown_not_zero(self):
        w = sample({"default_routes": -1, "errors": ";route"})
        self.assertEqual(w["qualidade"], "parcial")
        self.assertEqual(wan_signals(w, utcnow())["rota:main"], "dados_indisponiveis")

    def test_installer_is_observation_only(self):
        source = (
            Path(__file__).resolve().parent.parent / "routeros" / "instalar_observacao_wan_v1.rsc"
        ).read_text()
        self.assertIn("policy=read dont-require-permissions=no", source)
        self.assertNotIn("/ip dhcp-client enable", source)
        self.assertNotIn("/ip route add", source)
        self.assertNotIn("/file ", source)
        self.assertNotIn("/system reboot", source)


class FindingTests(unittest.TestCase):
    def codes(self, w):
        return {f["codigo"] for f in findings(w)["problemas"]}

    def test_disabled_client_still_identified_when_invalid_flag_is_unavailable(self):
        for value in (None, ""):
            w = sample(
                client={
                    "disabled": True,
                    "invalid": value,
                    "status": "stopped",
                    "address": "",
                    "gateway": "",
                }
            )
            self.assertEqual(wan_signals(w, utcnow()), {"dhcp:wan": "cliente_desabilitado"})
            self.assertEqual(self.codes(w), {"cliente_dhcp_desabilitado"})

    def test_unavailable_flags_never_imply_a_healthy_client(self):
        for field in ("disabled", "invalid"):
            w = sample(client={field: None})
            self.assertEqual(wan_signals(w, utcnow()), {"dhcp:wan": "dados_indisponiveis"})
            self.assertEqual(findings(w)["classificacao"], "inconclusivo")

    def test_known_invalid_flag_is_preserved_when_disabled_is_unknown(self):
        w = sample(client={"disabled": None, "invalid": True})
        self.assertEqual(self.codes(w), {"cliente_dhcp_invalido"})

    def test_text_no_is_false_and_does_not_create_disabled_alarm(self):
        self.assertEqual(
            wan_signals(sample(client={"disabled": "no", "invalid": "no"}), utcnow()), {}
        )

    def test_other_wan_faults_survive_unavailable_dhcp_flag(self):
        w = sample(
            {"ipv4_count": 0, "default_routes": 0, "dns_servers": 0, "free_hdd": 1024},
            client={"invalid": None},
        )
        self.assertEqual(
            self.codes(w),
            {
                "observacao_wan_incompleta",
                "wan_sem_ipv4",
                "rota_padrao_ausente",
                "dns_upstream_ausente",
                "pouco_espaco_livre",
            },
        )

    def test_normal_expanded_observation_has_no_deviation(self):
        self.assertEqual(wan_signals(sample(), utcnow()), {})

    def test_dhcp_disabled_detected_with_link_up(self):
        w = sample(client={"disabled": True, "status": "stopped", "address": "", "gateway": ""})
        self.assertIn("cliente_dhcp_desabilitado", self.codes(w))
        self.assertEqual(findings(w)["classificacao"], "desvios_observados")
        self.assertIsNone(
            next(f for f in findings(w)["problemas"] if f["codigo"] == "cliente_dhcp_desabilitado")[
                "correcao_disponivel"
            ]
        )

    def test_missing_dhcp_expected_even_if_static_address_and_route_exist(self):
        self.assertEqual(
            self.codes(sample({"dhcp_count": 0, "dhcp": ""})), {"cliente_dhcp_ausente"}
        )

    def test_multiple_dhcp_clients(self):
        self.assertIn("clientes_dhcp_ambiguos", self.codes(sample({"dhcp_count": 2, "dhcp": ""})))

    def test_invalid_client_flag_does_not_infer_physical_cause(self):
        r = findings(sample(client={"invalid": True}))
        self.assertIn("cliente_dhcp_invalido", {f["codigo"] for f in r["problemas"]})
        self.assertTrue(all(f["causa_fisica"] == "nao_determinada" for f in r["problemas"]))

    def test_negotiation_is_observation_not_server_failure(self):
        for status in ("searching", "requesting", "error", "stopped", ""):
            r = findings(sample(client={"status": status, "address": "", "gateway": ""}))
            f = next(f for f in r["problemas"] if f["codigo"] == "dhcp_sem_concessao_estavel")
            self.assertIn("negociacao", f["proxima_verificacao"])
            self.assertIsNone(f["correcao_disponivel"])

    def test_renewing_and_rebinding_with_address_not_declared_lost_lease(self):
        for status in ("renewing", "rebinding"):
            self.assertNotIn(
                "dhcp_sem_concessao_estavel", self.codes(sample(client={"status": status}))
            )

    def test_no_ipv4_default_route_and_dns_are_distinct_observations(self):
        self.assertTrue(
            {"wan_sem_ipv4", "rota_padrao_ausente", "dns_upstream_ausente"}.issubset(
                self.codes(sample({"ipv4_count": 0, "default_routes": 0, "dns_servers": 0}))
            )
        )

    def test_doh_prevents_false_missing_dns_alert(self):
        self.assertNotIn(
            "dns_upstream_ausente", self.codes(sample({"dns_servers": 0, "doh_configured": True}))
        )

    def test_default_route_does_not_prove_internet(self):
        r = findings(sample())
        self.assertIn("fim a fim", r["limite"])
        self.assertEqual(r["problemas"], [])

    def test_one_logical_cpu_saturated_with_low_average_is_detected(self):
        m = {
            "tem_dados": True,
            "cpu_media_pct": 27.25,
            "cpu_indices_pct": {"1": 100, "2": 3, "3": 4, "4": 2},
            "memoria_pct": 24,
        }
        r = findings(sample(), metrics=m)
        self.assertIn("cpu_indice:1", r["sinais"])
        self.assertIn("indice_cpu_elevado", {p["codigo"] for p in r["problemas"]})

    def test_average_cpu_and_ram_high(self):
        r = findings(metrics={"tem_dados": True, "cpu_media_pct": 95, "memoria_pct": 92})
        self.assertEqual({p["codigo"] for p in r["problemas"]}, {"cpu_elevada", "ram_elevada"})

    def test_low_flash_space_is_only_an_alert(self):
        r = findings(sample({"free_hdd": 1024}))
        f = next(p for p in r["problemas"] if p["codigo"] == "pouco_espaco_livre")
        self.assertIsNone(f["correcao_disponivel"])
        self.assertIn("nenhuma remocao", f["proxima_verificacao"])

    def test_missing_partial_old_future_data_are_not_healthy(self):
        for seconds in (-121, 30):
            w = sample()
            w["utc"] = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
            self.assertEqual(set(wan_signals(w, utcnow())), set(SERVICE_KEYS))
        self.assertEqual(
            {p["codigo"] for p in findings({"tem_dados": False, "erro": "permissao"})["problemas"]},
            {"observacao_wan_incompleta"},
        )

    def test_ether5_no_cable_not_an_anomaly_and_ether2_remains_protected(self):
        self.assertEqual(findings(sample())["problemas"], [])
        ss = support.fresh_states()
        ss["ether2"].update(admin_status=2, oper_status=2)
        self.assertTrue(
            all(f["correcao_disponivel"] is None for f in findings(sample(), data=ss)["problemas"])
        )

    def test_contradictory_interface_state_does_not_advertise_a_correction(self):
        ss = support.fresh_states()
        ss["ether1"].update(admin_status=2, oper_status=1)
        self.assertTrue(
            all(f["correcao_disponivel"] is None for f in findings(sample(), data=ss)["problemas"])
        )

    def test_collection_gap_does_not_resolve_known_dhcp_incident(self):
        with tempfile.TemporaryDirectory() as t:
            tracker = IncidentTracker(Path(t) / "i.json", load_profile())
            s = wan_signals(
                sample(client={"disabled": True, "status": "stopped", "address": ""}), utcnow()
            )
            tracker.observe(s)
            tracker.complete(list(s), "sem_acao_executavel")
            tracker.observe(wan_signals({"tem_dados": False}, utcnow()))
            self.assertIn("dhcp:wan", tracker.entries)
            self.assertNotIn("dhcp:wan", tracker.observe(s))


class StructuredDiagnosisTests(unittest.TestCase):
    def sample(self):
        p = packet()
        p["problemas_observados"] = [
            {
                "id": "D0",
                "codigo": "cliente_dhcp_desabilitado",
                "problema": "DHCP desabilitado.",
                "evidencias": ["E0"],
                "qualidade": "observado",
                "correcao_disponivel": None,
            }
        ]
        doc = proposal("investigar")
        doc["problemas_identificados"] = [
            {"id": "D0", "explicacao": "Cliente desabilitado na observacao; conferir manutencao."}
        ]
        return p, doc

    def test_no_executable_action_does_not_hide_problem(self):
        p, d = self.sample()
        p["acoes_elegiveis_python"] = []
        self.assertEqual(proposal_schema(p)["properties"]["acao"]["enum"], ["investigar"])
        self.assertEqual(validate_proposal(d, p)["problemas_identificados"][0]["id"], "D0")

    def test_missing_duplicate_or_invented_problem_id_is_rejected(self):
        for rows in (
            [],
            [{"id": "D999", "explicacao": "x"}],
            [{"id": "D0", "explicacao": "x"}] * 2,
            [{"id": "D0", "explicacao": ""}],
        ):
            p, d = self.sample()
            d["problemas_identificados"] = rows
            with self.assertRaises(ValueError):
                validate_proposal(d, p)

    def test_no_schema_extension_for_legacy_packets(self):
        self.assertNotIn("problemas_identificados", proposal_schema(packet())["properties"])

    def test_empty_findings_require_empty_list(self):
        p, d = self.sample()
        p["problemas_observados"] = []
        d["problemas_identificados"] = []
        self.assertEqual(validate_proposal(d, p)["problemas_identificados"], [])


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_dhcp_with_null_invalid_flag_returns_partial_observation(self):
        client = WANObserver("tcc-escrita", "12345678", "abcdefgh")
        client.target = "read"
        client.write_target = "no-retry"

        async def walk(*a, **k):
            yield {NAMES + ".7": SCRIPT}

        d = payload()
        d["dhcp"].update(disabled=True, invalid=None, status="stopped", address="", gateway="")
        get = AsyncMock(
            side_effect=[
                {DESC: "RouterOS RB750Gr3", UPTIME: 1000},
                {EXECUTE + ".7": MARKER + json.dumps(d)},
                {UPTIME: 1100},
            ]
        )
        try:
            with (
                patch("observacao_wan.get_cmd", get),
                patch("observacao_wan.walk_cmd", walk),
                patch("observacao_wan.decoded", side_effect=lambda x: x),
            ):
                w = await client.observe()
            self.assertTrue(w["tem_dados"])
            self.assertEqual(w["qualidade"], "parcial")
            self.assertEqual(wan_signals(w, utcnow())["dhcp:wan"], "cliente_desabilitado")
            self.assertEqual(get.call_count, 3)
        finally:
            client.close()

    async def test_failed_response_records_only_structural_diagnostics(self):
        client = WANObserver("tcc-escrita", "12345678", "abcdefgh")
        client.target = "read"
        client.write_target = "no-retry"

        async def walk(*a, **k):
            yield {NAMES + ".7": SCRIPT}

        raw = "1\n1\n" + MARKER + json.dumps(payload())
        get = AsyncMock(
            side_effect=[{DESC: "RouterOS RB750Gr3", UPTIME: 1000}, {EXECUTE + ".7": raw}]
        )
        try:
            with (
                patch("observacao_wan.get_cmd", get),
                patch("observacao_wan.walk_cmd", walk),
                patch("observacao_wan.decoded", side_effect=lambda x: x),
            ):
                w = await client.observe()
            self.assertFalse(w["tem_dados"])
            self.assertIn("Saida extra", w["erro"])
            self.assertEqual(w["diagnostico_resposta"]["posicao_marcador"], 4)
            self.assertNotIn("192.168.0.121", json.dumps(w))
            self.assertEqual(get.call_count, 2)
        finally:
            client.close()

    async def test_get_executes_only_discovered_observer_and_checks_uptime(self):
        client = WANObserver("tcc-escrita", "12345678", "abcdefgh")
        client.target = "read"
        client.write_target = "no-retry"
        oid = EXECUTE + ".7"

        async def walk(*args, **kwargs):
            yield {NAMES + ".7": SCRIPT, NAMES + ".8": "tcc-correct-something"}

        get = AsyncMock(
            side_effect=[
                {DESC: "RouterOS RB750Gr3", UPTIME: 1000},
                {oid: MARKER + json.dumps(payload())},
                {UPTIME: 1100},
            ]
        )
        try:
            with (
                patch("observacao_wan.get_cmd", get),
                patch("observacao_wan.walk_cmd", walk),
                patch("observacao_wan.decoded", side_effect=lambda x: x),
            ):
                w = await client.observe()
            self.assertTrue(w["tem_dados"])
            self.assertEqual(get.call_count, 3)
            self.assertEqual(get.call_args_list[1].args[2], "no-retry")
        finally:
            client.close()

    async def test_timeout_not_retried_and_not_success(self):
        client = WANObserver("tcc-escrita", "12345678", "abcdefgh")
        client.target = "read"
        client.write_target = "no-retry"

        async def walk(*a, **k):
            yield {NAMES + ".7": SCRIPT}

        get = AsyncMock(side_effect=[{DESC: "RouterOS RB750Gr3", UPTIME: 1000}, TimeoutError()])
        try:
            with (
                patch("observacao_wan.get_cmd", get),
                patch("observacao_wan.walk_cmd", walk),
                patch("observacao_wan.decoded", side_effect=lambda x: x),
            ):
                w = await client.observe()
            self.assertFalse(w["tem_dados"])
            self.assertEqual(get.call_count, 2)
        finally:
            client.close()

    async def test_reboot_during_snapshot_invalidates_data(self):
        client = WANObserver("tcc-escrita", "12345678", "abcdefgh")
        client.target = "read"
        client.write_target = "no-retry"

        async def walk(*a, **k):
            yield {NAMES + ".7": SCRIPT}

        get = AsyncMock(
            side_effect=[
                {DESC: "RouterOS RB750Gr3", UPTIME: 1000},
                {EXECUTE + ".7": MARKER + json.dumps(payload())},
                {UPTIME: 10},
            ]
        )
        try:
            with (
                patch("observacao_wan.get_cmd", get),
                patch("observacao_wan.walk_cmd", walk),
                patch("observacao_wan.decoded", side_effect=lambda x: x),
            ):
                w = await client.observe()
            self.assertFalse(w["tem_dados"])
            self.assertIn("regrediu", w["erro"])
        finally:
            client.close()


class ExpandedIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def run_scenario(self, **kwargs):
        helper = support.ContinuousIntegrationTests()
        helper.addCleanup = self.addCleanup
        return await helper.scenario(**kwargs)

    async def test_partial_disabled_dhcp_reaches_models_without_any_set(self):
        w = sample(
            client={
                "disabled": "yes",
                "invalid": None,
                "status": "stopped",
                "address": "",
                "gateway": "",
            }
        )
        r = await self.run_scenario(wan_sample=w)
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(len(r.rev.calls), 1)
        p, d = r.rev.calls[0]
        self.assertEqual(d["acao"], "investigar")
        self.assertEqual(
            {f["codigo"] for f in p["problemas_observados"]}, {"cliente_dhcp_desabilitado"}
        )

    async def test_dhcp_partial_to_recovery_clears_incident(self):
        with tempfile.TemporaryDirectory() as t:
            tracker = IncidentTracker(Path(t) / "i.json", load_profile())
            w = sample(
                client={"disabled": True, "invalid": None, "status": "stopped", "address": ""}
            )
            self.assertIn("dhcp:wan", tracker.observe(wan_signals(w, utcnow())))
            tracker.complete(["dhcp:wan"], "sem_acao_executavel")
            tracker.observe(wan_signals(sample(client={"invalid": None}), utcnow()))
            self.assertIn("dhcp:wan", tracker.entries)
            tracker.observe(wan_signals(sample(), utcnow()))
            self.assertNotIn("dhcp:wan", tracker.entries)

    async def test_healthy_expanded_monitor_does_not_call_models(self):
        r = await self.run_scenario(wan_sample=sample(), cycles=2)
        self.assertEqual(r.backend.calls, [])
        self.assertEqual(r.rev.calls, [])
        self.assertEqual(r.dev.writes, [])

    async def test_dhcp_disabled_identified_without_interface_fault_or_set(self):
        r = await self.run_scenario(
            wan_sample=sample(
                {"ipv4_count": 0, "default_routes": 0},
                client={"disabled": True, "status": "stopped", "address": "", "gateway": ""},
            ),
            cycles=2,
        )
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.prompts, [])
        self.assertEqual(len(r.rev.calls), 1)
        p, d = r.rev.calls[0]
        self.assertIn("cliente_dhcp_desabilitado", {f["codigo"] for f in p["problemas_observados"]})
        self.assertEqual(d["acao"], "investigar")
        self.assertEqual(len(d["problemas_identificados"]), 3)
        self.assertEqual(r.results[-1]["resultado"], "monitoramento_sem_nova_analise")

    async def test_independent_interface_correction_still_works_with_expanded_observation(self):
        r = await self.run_scenario(wan_sample=sample(), disabled=["ether5"])
        self.assertEqual(r.dev.writes, [6])
        self.assertEqual(r.results[0]["resultado"], "habilitacao_confirmada")

    async def test_dhcp_issue_and_model_failure_still_leave_verified_finding(self):
        r = await self.run_scenario(
            wan_sample=sample(client={"disabled": True, "status": "stopped", "address": ""}),
            model_failure=True,
        )
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.rev.calls, [])
        self.assertTrue(
            any(
                "cliente_dhcp_desabilitado"
                in {f["codigo"] for f in d["diagnostico_ampliado"]["problemas"]}
                for d in r.docs
            )
        )

    async def test_missing_script_is_inconclusive_and_does_not_burn_api_each_cycle(self):
        r = await self.run_scenario(
            wan_sample={"tem_dados": False, "erro": "Instale script."}, cycles=2
        )
        self.assertEqual(r.rev.calls, [])
        self.assertEqual(r.backend.calls, [])
        self.assertEqual(r.dev.writes, [])
        self.assertEqual(r.results[0]["resultado"], "observacao_wan_indisponivel")

    async def test_missing_wan_observation_does_not_hide_independent_port_fault(self):
        r = await self.run_scenario(
            wan_sample={"tem_dados": False, "erro": "Instale script."}, disabled=["ether5"]
        )
        p, d = r.rev.calls[0]
        self.assertEqual(
            {f["codigo"] for f in p["problemas_observados"]},
            {"estado_administrativo_divergente", "observacao_wan_incompleta"},
        )
        self.assertEqual(r.dev.writes, [6])

    async def test_low_mean_but_hot_logical_index_triggers_analysis(self):
        r = await self.run_scenario(
            wan_sample=sample(),
            metrics={
                "tem_dados": True,
                "cpu_media_pct": 27.25,
                "cpu_indices_pct": {"1": 100, "2": 3, "3": 4, "4": 2},
                "memoria_pct": 24,
            },
        )
        self.assertEqual(len(r.rev.calls), 1)
        self.assertEqual(r.dev.writes, [])
        self.assertIn(
            "indice_cpu_elevado", {f["codigo"] for f in r.rev.calls[0][0]["problemas_observados"]}
        )

    async def test_remote_failure_never_hides_facts_and_never_writes(self):
        r = await self.run_scenario(wan_sample=sample({"dns_servers": 0}), review_status="timeout")
        self.assertEqual(r.dev.writes, [])
        self.assertTrue(
            any(
                "dns_upstream_ausente"
                in {f["codigo"] for f in d["diagnostico_ampliado"]["problemas"]}
                for d in r.docs
            )
        )

    async def test_packet_with_multiple_failures_fits_local_character_budget(self):
        w = sample(
            {"ipv4_count": 0, "default_routes": 0, "dns_servers": 0, "free_hdd": 1024},
            client={"disabled": True, "status": "stopped", "address": ""},
        )
        r = await self.run_scenario(
            wan_sample=w,
            disabled=["ether5"],
            linkdown=["ether1"],
            metrics={"tem_dados": True, "cpu_media_pct": 95, "memoria_pct": 92},
        )
        p, d = r.rev.calls[0]
        msg = [
            {"role": "system", "content": PROPOSAL_SYSTEM},
            {"role": "user", "content": json.dumps(p, ensure_ascii=False, separators=(",", ":"))},
        ]
        size = len(dumps(msg)) + len(dumps(proposal_schema(p)))
        self.assertLessEqual(size, 12500)
        self.assertTrue(
            all(set(f["evidencias"]).issubset(references(p)) for f in p["problemas_observados"])
        )
        self.assertEqual(r.dev.writes, [6])
