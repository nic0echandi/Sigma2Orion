#!/usr/bin/env python3
"""Ejecuta sigma2orion una sola vez y termina (modo a demanda: manual o disparado por cron)."""
from sigma2orion_core import run_once

if __name__ == "__main__":
    run_once()