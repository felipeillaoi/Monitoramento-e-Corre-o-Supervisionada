import argparse
import sqlite3
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Exibe os ultimos ciclos sem exigir um programa externo para SQLite."
    )
    parser.add_argument(
        "--banco", type=Path, default=Path(__file__).resolve().parent / "dados" / "monitoramento.db"
    )
    args = parser.parse_args()
    if not args.banco.is_file():
        raise SystemExit("Banco ainda nao encontrado. Execute o coletor primeiro.")
    db = sqlite3.connect(args.banco.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        print("Ciclos por status:")
        for status, count in db.execute("SELECT status,COUNT(*) FROM ciclos GROUP BY status"):
            print(f"  {status}: {count}")
        print("\nUltimos 10 ciclos (horarios UTC):")
        query = """
            SELECT c.id,c.instante_utc,c.status,
                   MAX(CASE WHEN m.metrica='cpu_media_indices_pct' THEN m.valor END),
                   MAX(CASE WHEN m.metrica='memoria_pct' THEN m.valor END)
            FROM ciclos c LEFT JOIN metricas m ON m.ciclo_id=c.id
            GROUP BY c.id ORDER BY c.id DESC LIMIT 10
        """
        for cycle, timestamp, status, cpu, ram in db.execute(query):
            cpu_text = "N/D" if cpu is None else f"{cpu:.2f}%"
            ram_text = "N/D" if ram is None else f"{ram:.2f}%"
            print(f"  {cycle} | {timestamp} | {status} | CPU {cpu_text} | RAM {ram_text}")
        latest = db.execute("SELECT diagnostico FROM ciclos ORDER BY id DESC LIMIT 1").fetchone()
        if latest and latest[0] != "[]":
            print("\nDiagnostico do ultimo ciclo: " + latest[0])
    finally:
        db.close()


if __name__ == "__main__":
    main()
