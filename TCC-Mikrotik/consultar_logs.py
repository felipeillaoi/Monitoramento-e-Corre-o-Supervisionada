import argparse
import json
from logs_snmp import DEFAULT_DB, query_archive


def main():
    parser = argparse.ArgumentParser(
        description="Consulta o arquivo SQLite de logs coletados por SNMP, sem acessar a RB."
    )
    parser.add_argument(
        "--texto", default="", help="Texto literal na mensagem, por exemplo ether1."
    )
    parser.add_argument("--topico", default="", help="Texto literal nos topicos, por exemplo dhcp.")
    parser.add_argument("--limite", type=int, default=12)
    parser.add_argument(
        "--completo",
        action="store_true",
        help="Exibe mensagem inteira; arquivo nunca trunca mensagens.",
    )
    parser.add_argument("--banco", type=type(DEFAULT_DB), default=DEFAULT_DB)
    args = parser.parse_args()
    data = query_archive(
        args.banco,
        text=args.texto,
        topic=args.topico,
        limit=args.limite,
        max_chars=65536 if args.completo else 500,
    )
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
