import argparse
import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from contexto_supervisionado import fingerprint
from revisor_gpt import GPTReviewer, DEFAULT_MODEL


def main():
    parser = argparse.ArgumentParser(
        description="Teste REAL da API usando somente evidencias sinteticas; nao conecta ao MikroTik."
    )
    parser.add_argument("--modelo-gpt", default=DEFAULT_MODEL)
    args = parser.parse_args()
    print("Teste real da API com dados SINTETICOS. Pode gerar cobranca de tokens. Sem SNMP/SET.")
    key = os.environ.get("OPENAI_API_KEY") or getpass(
        "Chave API OpenAI (oculta, somente em memoria): "
    )
    packet = {
        "cenario": "TESTE SINTETICO, sem equipamento conectado",
        "pergunta": "Ha evidencias suficientes para alterar a configuracao?",
        "evidencias": [{"id": "E0", "dados": {"cpu_pct": 20, "ram_pct": 25, "idade_s": 1}}],
        "acoes_elegiveis_python": [],
        "limites": "Sem evidencias de causa e sem acao executavel.",
    }
    proposal = {
        "resumo": "CPU e RAM sem sobrecarga nesses valores; nao certifica saude geral.",
        "acao": "nenhuma",
        "evidencias": ["E0"],
        "justificativa": "Sem evidencia que justifique alteracao.",
    }
    pid = fingerprint({"contexto": packet, "proposta": proposal})
    reviewer = GPTReviewer(key.strip(), args.modelo_gpt)
    result = asyncio.run(reviewer.review(packet, proposal, pid, ["E0"]))
    record = {
        "versao": "0.4.6",
        "tipo": "teste_API_sintetico",
        "fim_utc": datetime.now(timezone.utc).isoformat(),
        "resultado": result,
    }

    output = json.dumps(record, ensure_ascii=False, indent=2)
    if key:
        output = output.replace(key, "[CHAVE_REMOVIDA]")
    folder = Path(__file__).resolve().parent / "dados" / "testes_api"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8] + ".json"
    )
    path.write_text(output, encoding="utf-8")
    print("Status:", result["status"])
    print("Codigo API:", result.get("codigo_api") or "nao informado")
    if result.get("parecer"):
        print("Decisao:", result["parecer"]["decisao"])
        print(
            "Justificativa:",
            result["parecer"]["justificativa"].replace(key, "[CHAVE_REMOVIDA]")
            if key
            else result["parecer"]["justificativa"],
        )
    print("Registro:", path)
    return 0 if result["status"] == "concluida" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        raise SystemExit("Teste interrompido.")
