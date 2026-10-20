import unittest
from teste_logs_snmp import find_script, parse_output, NAMES
from snmp_ether5 import TestFailure


class LogTests(unittest.TestCase):
    def test_exact_script_discovered_without_guessing_index(self):
        self.assertEqual(
            find_script({NAMES + ".7": "outro-script", NAMES + ".42": "tcc-logs-interfaces"}), "42"
        )

    def test_missing_or_duplicate_script_blocks(self):
        for rows in (
            {NAMES + ".1": "outro"},
            {NAMES + ".1": "tcc-logs-interfaces", NAMES + ".2": "tcc-logs-interfaces"},
        ):
            with self.assertRaises(TestFailure):
                find_script(rows)

    def test_output_must_have_marker_and_bounded_rows(self):
        self.assertEqual(
            parse_output("TCCLOGSv1\n11:35:01 | ether1 link down"), ["11:35:01 | ether1 link down"]
        )
        for output in ("output", "TCCLOGSv1\nsem-formato", "TCCLOGSv1" + "\n10:00 | x" * 6):
            with self.assertRaises(TestFailure):
                parse_output(output)

    def test_empty_filter_not_fault_evidence(self):
        self.assertEqual(parse_output("TCCLOGSv1\nSEM_ENTRADAS_NO_FILTRO"), [])
