#!/usr/bin/env python3
"""Corre sigma2orion como servicio continuo: revisa reglas nuevas cada CHECK_INTERVAL_MINUTES (.env)."""
import signal, time
from sigma2orion_core import run_once, log, CHECK_INTERVAL_MINUTES

_stop_requested = False


def _handle_stop_signal(signum, frame):
    global _stop_requested
    log.info(f"Señal {signum} recibida, se detendra al terminar la corrida actual.")
    _stop_requested = True


def main():
    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    log.info(f"Iniciando como servicio, se revisara cada {CHECK_INTERVAL_MINUTES} minutos (CHECK_INTERVAL_MINUTES en .env).")
    while not _stop_requested:
        try:
            run_once()
        except Exception as exc:
            log.error(f"Error inesperado en la corrida, se continua en el proximo ciclo: {exc}")

        if _stop_requested:
            break
        log.info(f"Esperando {CHECK_INTERVAL_MINUTES} minutos hasta la proxima revision.")
        time.sleep(CHECK_INTERVAL_MINUTES * 60)

    log.info("Servicio detenido.")


if __name__ == "__main__":
    main()
