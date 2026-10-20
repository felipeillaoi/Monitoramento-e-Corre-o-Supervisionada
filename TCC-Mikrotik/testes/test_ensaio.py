import json
import tempfile
import unittest
from pathlib import Path
from avaliar_logs import make_cases, REFERENCE
from analise_logs import catalogue
from resumir_ensaio import summarize


class EnsaioTests(unittest.TestCase):
    def test_independent_golden_cases(self):
        cases = make_cases()
        self.assertEqual(len(cases), 14)
        for case in cases:
            with self.subTest(case=case["nome"]):
                _, expected = catalogue(case["evidencias"], REFERENCE, case["fuso"])
                self.assertEqual(expected, case["esperado"])

    def test_summary_separates_SET_GET_incomplete_replay_and_wrong_version(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            events = [
                {"evento": "inventario", "utc": "2026-10-13T17:00:00+00:00"},
                {"evento": "SET_a_enviar"},
                {"evento": "resposta_SET", "resultado": "aceito"},
                {
                    "evento": "GET_pos_SET",
                    "utc": "2026-10-13T17:00:10+00:00",
                    "dados": {"admin_status": 1},
                },
            ]
            base = {
                "versao": "0.3.5",
                "inicio_utc": "2026-10-13T17:00:00+00:00",
                "fim_utc": "2026-10-13T17:00:15+00:00",
                "status_execucao": "concluida",
                "diagnostico": {"classificacao": "suspeita"},
                "investigacao_interfaces": {"eventos": events},
            }
            docs = [
                base,
                {"versao": "0.3.5", "diagnostico": None},
                {**base, "modo": "replay_logs_sem_snmp"},
                {**base, "versao": "0.3.4"},
            ]
            for i, doc in enumerate(docs):
                (root / (str(i) + ".json")).write_text(json.dumps(doc), encoding="utf-8")
            (root / "invalido.json").write_text("{", encoding="utf-8")
            summary = summarize(root.glob("*.json"), version="0.3.5")
            self.assertEqual(summary["registros_analisados"], 2)
            self.assertEqual(summary["analises_sem_fim"], 1)
            self.assertEqual(summary["intencoes_SET"], 1)
            self.assertEqual(summary["SETs_aceitos"], 1)
            self.assertEqual(summary["analises_com_GET_admin_1_apos_SET"], 1)
            self.assertEqual(summary["tempos_observacao_inicial_ate_GET_admin_1_s"], [10])
            self.assertEqual(len(summary["arquivos_invalidos"]), 1)


if __name__ == "__main__":
    unittest.main()
