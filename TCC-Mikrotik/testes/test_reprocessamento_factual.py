import asyncio
import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock

from avaliar_revisor_factual import cases, reprocess, score_case, print_row, run
from revisor_gpt import resolve_factual_quote, validate_factual_quotes, InconsistentReview
from test_revisao_factual import audit, error

FIXTURE = Path(__file__).resolve().parent.parent / "casos" / "revisao_factual_v054_real.json"


class QuoteFormatTests(unittest.TestCase):
    def setUp(self):
        self.doc = cases()[1]["proposta"]
        self.text = self.doc["resumo"]

    def test_literal_and_known_outer_delimiters_match_same_original_text(self):
        for quote in (
            self.text,
            json.dumps(self.text),
            "'" + self.text + "'",
            "`" + self.text + "`",
            "“" + self.text + "”",
        ):
            with self.subTest(quote=quote):
                self.assertEqual(resolve_factual_quote(quote, self.doc)["texto"], self.text)

    def test_json_field_wrapper_matches_the_referenced_field(self):
        q = '"resumo":' + json.dumps(self.text)
        result = resolve_factual_quote(q, self.doc)
        self.assertEqual(result["texto"], self.text)
        self.assertEqual(result["campo"], "resumo")

    def test_text_field_prefix_is_supported(self):
        self.assertEqual(
            resolve_factual_quote("resumo: " + json.dumps(self.text), self.doc)["texto"], self.text
        )

    def test_field_wrapper_cannot_borrow_text_from_another_field(self):
        for quote in (
            '"justificativa":' + json.dumps(self.text),
            "justificativa: " + json.dumps(self.text),
        ):
            with self.assertRaises(InconsistentReview):
                resolve_factual_quote(quote, self.doc)

    def test_unknown_keys_multiple_keys_and_duplicates_are_not_known_wrappers(self):
        for quote in (
            '"inventado":' + json.dumps(self.text),
            '"resumo":' + json.dumps(self.text) + ',"justificativa":"x"',
            '"resumo":"inventado","resumo":' + json.dumps(self.text),
        ):
            with self.assertRaises(InconsistentReview):
                resolve_factual_quote(quote, self.doc)

    def test_paraphrase_or_changed_words_still_rejected(self):
        for quote in (
            "A ether1 esta com link ativo.",
            '"resumo":"A ether2 esta sem link fisico."',
            'resumo: ""',
        ):
            with self.assertRaises(InconsistentReview):
                resolve_factual_quote(quote, self.doc)

    def test_normalization_audit_preserves_original_review(self):
        q = '"resumo":' + json.dumps(self.text)
        doc = audit("p", "rejeitar", [error(q)])
        before = copy.deepcopy(doc)
        trace = []
        validate_factual_quotes(doc, self.doc, trace)
        self.assertEqual(doc, before)
        self.assertEqual(trace[0]["formato"], "campo_json")
        self.assertEqual(trace[0]["texto"], self.text)


class ReplayTests(unittest.TestCase):
    def replay(self, path=FIXTURE):
        with contextlib.redirect_stdout(io.StringIO()):
            return reprocess(path)

    def test_all_six_saved_responses_can_be_revalidated_offline(self):
        rows, source = self.replay()
        self.assertEqual(sum(r["acerto"] for r in rows), 6)
        self.assertEqual(sum(r["parecer_utilizavel"] for r in rows), 6)
        self.assertEqual(sum(r["erro_alvo_identificado"] is True for r in rows), 5)
        self.assertEqual(source["novas_chamadas_API"], 0)

    def test_extra_dns_critique_remains_visible_for_manual_review(self):
        rows, _ = self.replay()
        dns = next(r for r in rows if r["caso"] == "dns_do_pc_sem_teste")
        self.assertEqual(
            dns["criticas_adicionais_para_revisao_manual"], ['"Sem IPv4 ativo em ether1."']
        )

    def test_source_bytes_and_original_failed_status_are_preserved(self):
        before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        rows, _ = self.replay()
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), before)
        bad = next(r for r in rows if r["caso"] == "confunde_link_com_ip")["revisao"]
        self.assertEqual(bad["validacao_anterior"]["status"], "parecer_inconsistente")

    def test_wrong_proposal_hash_is_not_revalidated_as_success(self):
        d = json.loads(FIXTURE.read_text())
        d["casos"][0]["revisao"]["proposta_id"] = "hash-alterado"
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "orig.json"
            path.write_text(json.dumps(d))
            rows, _ = self.replay(path)
        self.assertFalse(rows[0]["acerto"])
        self.assertFalse(rows[0]["parecer_utilizavel"])

    def test_terminal_preamble_from_uploaded_transcription_is_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "copia.txt"
            path.write_text("C:\\teste>type registro.json\n" + FIXTURE.read_text())
            rows, _ = self.replay(path)
        self.assertEqual(sum(r["acerto"] for r in rows), 6)

    def test_rejection_citing_only_correct_non_target_statement_is_not_a_full_hit(self):
        c = cases()[3]
        quote = c["proposta"]["problemas_identificados"][1]["explicacao"]
        review = {"status": "concluida", "parecer": audit("p", "rejeitar", [error(quote)])}
        row = score_case(c, review)
        self.assertTrue(row["decisao_concordante"])
        self.assertFalse(row["erro_alvo_identificado"])
        self.assertFalse(row["acerto"])

    def test_printed_summary_exposes_protocol_failure_even_when_decision_matches(self):
        review = {
            "status": "parecer_inconsistente",
            "parecer": audit("p", "rejeitar", [error()]),
            "motivo_inconsistencia": "Trecho inexistente",
        }
        row = score_case(cases()[1], review)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_row(row)
        self.assertIn("parecer_inconsistente", output.getvalue())
        self.assertIn("Trecho inexistente", output.getvalue())

    def test_reprocessing_never_constructs_the_api_client(self):
        args = SimpleNamespace(reprocessar=FIXTURE)
        with (
            patch(
                "avaliar_revisor_factual.GPTReviewer",
                side_effect=AssertionError("API nao deve ser usada"),
            ),
            patch("avaliar_revisor_factual.save_report", Mock()) as save,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            asyncio.run(run(args))
        self.assertEqual(save.call_count, 1)


if __name__ == "__main__":
    unittest.main()
