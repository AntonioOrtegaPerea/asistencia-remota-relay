"""Servidor Relay independiente (CLI) para desplegar en VPS, Docker, Render o Railway."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os

from remote_desk.relay import RelayServer


def parse_args() -> argparse.Namespace:
    default_port = int(os.environ.get("PORT", "8765"))
    parser = argparse.ArgumentParser(
        description="WinRemoteDesk Relay Server — Puente WebSocket seguro para control remoto por Internet."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("RELAY_HOST", "0.0.0.0"),
        help="Interfaz de escucha (por defecto: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"Puerto TCP/WebSocket (por defecto: {default_port} o variable PORT)",
    )
    return parser.parse_args()


async def _run(host: str, port: int) -> None:
    server = RelayServer(host=host, port=port)
    await server.serve_forever()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args()
    try:
        asyncio.run(_run(args.host, args.port))
    except KeyboardInterrupt:
        logging.info("Servidor Relay detenido por el usuario.")


if __name__ == "__main__":
    main()
