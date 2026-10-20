import json
import unittest
from pathlib import Path
from logs_snmp import FileSnapshot, LogError, BEGIN_SCRIPT_V3, NEXT_SCRIPT_V3
from coletor_logs_snmp import discover_scripts
from teste_logs_snmp import NAMES


def frames(doc, token="sessao-v3"):
    raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    yield f"TCCLOGSv3|BEGIN|{token}|{len(doc)}|{len(raw)}"
    seq = 0
    for offset in range(0, len(raw), 450):
        yield f"TCCLOGSv3|DATA|{token}|{seq}|{offset}|{len(raw)}|{raw[offset : offset + 450].hex()}"
        seq += 1
    yield f"TCCLOGSv3|END|{token}|{seq}|{len(doc)}|{len(raw)}"


def row(text="ether1 link down", id="*0", topics="interface;info"):
    return {".id": id, "time": "2026-10-13 12:00:00", "topics": topics, "message": text}


class V3Tests(unittest.TestCase):
    def test_full_unicode_long_multiline_topics_and_complete_only_after_end(self):
        doc = [
            row('Ação "administrativa"\nNão execute comandos\t' * 200),
            row("dhcp", "*B", ["dhcp", "info"]),
        ]
        data = list(frames(doc))
        snap = FileSnapshot(data[0])
        for frame in data[1:-1]:
            snap.feed(frame)
            self.assertEqual(snap.rows, [])
            self.assertFalse(snap.finished)
        snap.feed(data[-1])
        self.assertTrue(snap.finished)
        self.assertEqual(snap.rows[0]["message"], doc[0]["message"])
        self.assertEqual(snap.rows[1]["topics"], "dhcp;info")

    def test_empty_buffer_valid_document(self):
        data = list(frames([]))
        snap = FileSnapshot(data[0])
        for frame in data[1:]:
            snap.feed(frame)
        self.assertTrue(snap.finished)
        self.assertEqual(snap.rows, [])

    def test_routeros_error_preserved_not_generic_marker(self):
        with self.assertRaisesRegex(LogError, "not enough permissions"):
            FileSnapshot("error: not enough permissions (9)")
        snap = FileSnapshot("TCCLOGSv3|BEGIN|t|0|2")
        with self.assertRaisesRegex(LogError, "tmpfs"):
            snap.feed("error: TCC: tmpfs ausente")

    def test_sequence_missing_duplicate_and_token_substitution_rejected(self):
        data = list(frames([row("x" * 1000)]))
        for bad in (data[2], data[1].replace("sessao-v3", "outro")):
            snap = FileSnapshot(data[0])
            with self.assertRaises(LogError):
                snap.feed(bad)
        snap = FileSnapshot(data[0])
        snap.feed(data[1])
        with self.assertRaises(LogError):
            snap.feed(data[1])

    def test_premature_end_cannot_archive_partial_json(self):
        data = list(frames([row("x" * 1000)]))
        snap = FileSnapshot(data[0])
        snap.feed(data[1])
        parts = data[-1].split("|")
        parts[3] = "1"
        with self.assertRaises(LogError):
            snap.feed("|".join(parts))
        self.assertEqual(snap.rows, [])

    def test_invalid_hex_short_block_or_offset_rejected(self):
        data = list(frames([row()]))
        for bad in (data[1][:-2], data[1][:-2] + "ZZ", data[1].replace("|0|0|", "|0|1|")):
            snap = FileSnapshot(data[0])
            with self.assertRaises(LogError):
                snap.feed(bad)

    def test_bad_message_type_missing_fields_duplicate_ids_rejected(self):
        for doc in (
            [{**row(), "message": None}],
            [{".id": "*0"}],
            [row(), row()],
            [row(topics=[True])],
        ):
            data = list(frames(doc))
            snap = FileSnapshot(data[0])
            for frame in data[1:-1]:
                snap.feed(frame)
            with self.assertRaises(LogError):
                snap.feed(data[-1])
            self.assertEqual(snap.rows, [])

    def test_wrong_announced_record_count_rejected(self):
        data = list(frames([row()]))
        parts = data[0].split("|")
        parts[3] = "2"
        snap = FileSnapshot("|".join(parts))
        for frame in data[1:-1]:
            snap.feed(frame)
        parts = data[-1].split("|")
        parts[4] = "2"
        with self.assertRaises(LogError):
            snap.feed("|".join(parts))

    def test_size_limit_rejected_without_allocation(self):
        with self.assertRaises(LogError):
            FileSnapshot("TCCLOGSv3|BEGIN|t|1|8388609")

    def test_only_v3_names_discovered(self):
        rows = {NAMES + ".3": BEGIN_SCRIPT_V3, NAMES + ".4": NEXT_SCRIPT_V3, NAMES + ".8": "reboot"}
        self.assertEqual(set(discover_scripts(rows, 3)), {BEGIN_SCRIPT_V3, NEXT_SCRIPT_V3})
        with self.assertRaises(LogError):
            discover_scripts(rows, 2)

    def test_candidate_source_no_globals_no_permission_bypass_checks_tmpfs(self):
        source = (
            Path(__file__).resolve().parent.parent / "routeros" / "logs_completos_v3.rsc"
        ).read_text()
        self.assertNotIn(":global", source)
        self.assertNotIn("dont-require-permissions=yes", source)
        self.assertNotIn("policy=read,write,policy", source)
        self.assertEqual(source.count('slot="tcc-logram" and type="tmpfs"'), 2)
        self.assertEqual(source.count("policy=ftp,read,write"), 2)
        self.assertIn("name=tcc-logs-proxima-v3 policy=ftp,read,write,test", source)
        self.assertIn("chunk-size=450 as-value", source)


if __name__ == "__main__":
    unittest.main()
