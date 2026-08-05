#!/usr/bin/env python3
"""Estadisticas de uso de sigma2orion.py: reglas creadas por mes y por anio.

Lee el archivo rules_stats.jsonl (generado automaticamente por sigma2orion.py
cada vez que procesa una regla) y muestra totales agrupados por mes y por anio.

Uso:
    python3 stats.py                 -> muestra reglas "created" por mes y anio
    python3 stats.py --all           -> incluye tambien descartadas/errores en el detalle
    python3 stats.py --year 2026     -> filtra solo un anio
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

STATS_FILE = "rules_stats.jsonl"

STATUS_LABELS = {
    "created": "Creadas",
    "discarded_fp": "Descartadas (riesgo FP)",
    "no_orion_type": "Sin Type equivalente",
    "error": "Con error",
}


def load_records(path=STATS_FILE):
    records = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        sys.exit(f"No se encontro '{path}'. Todavia no se registraron corridas de sigma2orion.py.")
    return records


def print_table(title, counter):
    print(f"\n{title}")
    print("-" * len(title))
    total = 0
    for key in sorted(counter):
        print(f"  {key}: {counter[key]}")
        total += counter[key]
    print(f"  TOTAL: {total}")


def main():
    parser = argparse.ArgumentParser(description="Estadisticas de reglas generadas por sigma2orion.py")
    parser.add_argument("--all", action="store_true", help="mostrar todos los estados, no solo las creadas")
    parser.add_argument("--year", type=str, default=None, help="filtrar por anio, ej: 2026")
    args = parser.parse_args()

    records = load_records()
    if args.year:
        records = [r for r in records if r.get("timestamp", "").startswith(args.year)]

    if not args.all:
        records = [r for r in records if r.get("status") == "created"]
        scope = "reglas CREADAS"
    else:
        scope = "todas las reglas procesadas"

    if not records:
        print(f"No hay datos ({scope}) para mostrar.")
        return

    by_month = Counter()
    by_year = Counter()
    by_status = Counter()

    for r in records:
        ts = r.get("timestamp", "")
        if len(ts) < 7:
            continue
        month_key = ts[:7]   # YYYY-MM
        year_key = ts[:4]    # YYYY
        by_month[month_key] += 1
        by_year[year_key] += 1
        by_status[STATUS_LABELS.get(r.get("status"), r.get("status", "desconocido"))] += 1

    print(f"Estadisticas de sigma2orion.py ({scope})")
    print_table("Reglas por mes", by_month)
    print_table("Reglas por anio", by_year)
    if args.all:
        print_table("Reglas por estado", by_status)


if __name__ == "__main__":
    main()
