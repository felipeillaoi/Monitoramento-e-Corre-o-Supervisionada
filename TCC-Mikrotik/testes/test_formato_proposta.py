import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from supervisao import proposal_schema, validate_proposal, supervise
from test_supervisionado import packet, proposal, opinion, FakeAgent
from test_investigacao_interfaces import Device
from snmp_ether5 import utcnow


class SchemaTests(unittest.TestCase):
    def test_declared_schema_limits_match_text_and_array_validator(self):
        fields = proposal_schema(packet())["properties"]
        for key in ("resumo", "justificativa"):
            self.assertEqual(fields[key]["minLength"], 1)
            self.assertEqual(fields[key]["maxLength"], 1200)
        for key in ("hipoteses", "limitacoes", "proximas_verificacoes"):
            self.assertEqual(fields[key]["maxItems"], 5)
            self.assertEqual(fields[key]["items"]["maxLength"], 350)
        self.assertEqual(fields["evidencias"]["maxItems"], 20)

    def test_actual_six_limitations_are_rejected_with_specific_message(self):
        d = json.loads(
            (
                Path(__file__).resolve().parent.parent / "casos/limite_lista_v056_real.json"
            ).read_text()
        )
        p = d["proposta"]
        before = copy.deepcopy(p)
        self.assertEqual(len(p["limitacoes"]), 6)
        with self.assertRaisesRegex(ValueError, "limitacoes: recebidos 6 itens; maximo 5"):
            validate_proposal(p, d["contexto"])
        self.assertEqual(p, before)

    def test_array_length_boundary_and_error_names(self):
        for key in ("hipoteses", "limitacoes", "proximas_verificacoes"):
            doc = proposal()
            doc[key] = ["x"] * 5
            validate_proposal(doc, packet())
            doc[key].append("x")
            with self.assertRaisesRegex(ValueError, key + ": recebidos 6"):
                validate_proposal(doc, packet())

    def test_item_length_boundary_is_enforced_and_named(self):
        doc = proposal()
        doc["limitacoes"] = ["x" * 350]
        validate_proposal(doc, packet())
        doc["limitacoes"] = ["x" * 351]
        with self.assertRaisesRegex(ValueError, "limitacoes: cada item"):
            validate_proposal(doc, packet())


class FormatReformulationTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(self, kind="six", repair=True, feedback=True):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            dev = Device()
            dev.data["ether5"].update(admin_status=2, oper_status=2)
            for row in dev.data.values():
                row["utc"] = utcnow()
            good = proposal()
            bad = copy.deepcopy(good)
            bad["limitacoes"] = ["Nao certifica conectividade."] * 6
            raw_bad = json.dumps(bad) if kind == "six" else '{"acao":'

            class Agent(FakeAgent):
                def __init__(self, *a):
                    super().__init__(*a)
                    self.calls = []

                async def chat(self, messages, **kwargs):
                    self.calls.append(copy.deepcopy(messages))
                    return {
                        "content": json.dumps(good) if repair and len(self.calls) > 1 else raw_bad
                    }

            class Reviewer:
                def __init__(self):
                    self.calls = 0

                async def review(self, p, doc, pid, ids):
                    self.calls += 1
                    return {
                        "status": "concluida",
                        "parecer": opinion(pid, action=doc["acao"]),
                        "contingencia_elegivel": False,
                    }

            agent = Agent(folder / "r.json", bad)
            rev = Reviewer()
            prompts = []
            with contextlib.redirect_stdout(io.StringIO()):
                r = await supervise(
                    agent,
                    dev,
                    dev,
                    packet(),
                    copy.deepcopy(dev.data),
                    rev,
                    True,
                    True,
                    folder,
                    {"tentativas": 0},
                    ask=lambda q: prompts.append(q) or "s",
                    pause=0,
                    feedback_enabled=feedback,
                )
            return r, dev, rev, prompts, agent.calls

    async def test_corrected_format_reaches_review_and_existing_executor_only_once(self):
        r, d, rev, prompts, calls = await self.scenario()
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertEqual(d.writes, [6])
        self.assertEqual(rev.calls, 1)
        self.assertEqual(len(prompts), 1)
        self.assertEqual(len(calls), 2)
        self.assertIn("limitacoes: recebidos 6", calls[1][-1]["content"])
        self.assertEqual(
            r["rodadas"][0]["erros_validacao_local"][0]["tipo"], "formato_proposta_invalido"
        )

    async def test_malformed_json_can_use_the_same_single_reformulation(self):
        r, d, rev, _, calls = await self.scenario(kind="json")
        self.assertEqual(r["resultado"], "habilitacao_confirmada")
        self.assertEqual(rev.calls, 1)
        self.assertIn("JSON invalido ou incompleto", calls[1][-1]["content"])
        self.assertEqual(d.writes, [6])

    async def test_repeated_bad_format_never_calls_api_consent_or_set(self):
        r, d, rev, prompts, calls = await self.scenario(repair=False)
        self.assertEqual(r["resultado"], "bloqueado_validacao_local")
        self.assertEqual(len(calls), 2)
        self.assertEqual(rev.calls, 0)
        self.assertEqual(prompts, [])
        self.assertEqual(d.writes, [])

    async def test_disabled_reformulation_blocks_after_first_invalid_output(self):
        r, d, rev, prompts, calls = await self.scenario(feedback=False)
        self.assertEqual(r["resultado"], "bloqueado_validacao_local")
        self.assertEqual(len(calls), 1)
        self.assertEqual(rev.calls, 0)
        self.assertEqual(prompts, [])
        self.assertEqual(d.writes, [])


if __name__ == "__main__":
    unittest.main()
