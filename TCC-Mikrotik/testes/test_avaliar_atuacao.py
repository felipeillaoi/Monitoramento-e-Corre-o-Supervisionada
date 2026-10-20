import json
import unittest

from avaliar_atuacao import cases, grade, aggregate
from atuacao_controlada import action_messages, policy


class ReplayTests(unittest.TestCase):
    def test_exact_input_contains_observations_not_expected_action(self):
        state = next(cases())
        observation = json.loads(action_messages(state)[1]["content"])
        self.assertEqual(
            observation, {"id": "A0", "interface": "ether5", "admin_status": 1, "oper_status": 1}
        )
        self.assertNotIn("acao", observation)

    def test_copied_states_wrong_action_is_failure(self):
        state = list(cases())[1]
        result = grade(
            json.dumps(
                {
                    "admin_status_lido": 1,
                    "oper_status_lido": 2,
                    "evidencia": "A0",
                    "acao": "habilitar_ether5",
                }
            ),
            state,
        )
        self.assertTrue(result["estados_corretos"])
        self.assertFalse(result["proposta_totalmente_correta"])
        self.assertTrue(result["habilitacao_indevida"])

    def test_correct_action_wrong_states_is_failure(self):
        state = list(cases())[1]
        result = grade(
            json.dumps(
                {
                    "admin_status_lido": 2,
                    "oper_status_lido": 2,
                    "evidencia": "A0",
                    "acao": "nenhuma",
                }
            ),
            state,
        )
        self.assertTrue(result["acao_correta"])
        self.assertFalse(result["proposta_totalmente_correta"])

    def test_invalid_output_stays_in_denominator(self):
        state = next(cases())
        bad = grade("not-json", state)
        good = grade(
            json.dumps(
                {
                    "admin_status_lido": 1,
                    "oper_status_lido": 1,
                    "evidencia": "A0",
                    "acao": "nenhuma",
                }
            ),
            state,
        )
        summary = aggregate([{"variante": "teste", **bad}, {"variante": "teste", **good}])["teste"]
        self.assertEqual(summary["tentativas"], 2)
        self.assertEqual(summary["propostas_totalmente_corretas"], 1)
        self.assertEqual(summary["propostas_invalidas"], 1)

    def test_cases_include_no_action_correction_and_abstention(self):
        counts = {"nenhuma": 0, "habilitar_ether5": 0, "inconclusivo": 0}
        for state in cases():
            counts[policy(state)] += 1
        self.assertEqual(counts, {"nenhuma": 4, "habilitar_ether5": 3, "inconclusivo": 5})


if __name__ == "__main__":
    unittest.main()
