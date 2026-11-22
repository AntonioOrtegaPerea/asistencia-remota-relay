"""Servidor Relay (Puente) por WebSocket para conectar equipos a través de Internet."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response

from .config import normalize_session_id
from .crypto import verify_auth_proof

logger = logging.getLogger("winremotedesk.relay")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60.0
MAX_MESSAGE_BYTES = 16 * 1024 * 1024  # 16 MB

_STATIC_MIME: dict[str, str] = {
    "/": "text/html; charset=utf-8",
    "/index.html": "text/html; charset=utf-8",
    "/app.js": "application/javascript; charset=utf-8",
    "/crypto.js": "application/javascript; charset=utf-8",
    "/sw.js": "application/javascript; charset=utf-8",
    "/manifest.json": "application/manifest+json; charset=utf-8",
    "/icon-192.png": "image/png",
    "/icon-512.png": "image/png",
    "/apple-touch-icon.png": "image/png",
}


def _get_web_console_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = Path(getattr(sys, "_MEIPASS")) / "remote_desk" / "web_console"
        if base.exists():
            return base
    return Path(__file__).resolve().parent / "web_console"


@dataclass
class RelaySession:
    session_id: str
    host_ws: ServerConnection
    salt_b64: str
    auth_key_b64: str
    client_ws: ServerConnection | None = None
    failed_attempts: int = 0
    locked_until: float = 0.0
    pending_nonces: dict[ServerConnection, bytes] = field(default_factory=dict)


class RelayServer:
    """Puente WebSocket seguro con verificación desafío-respuesta y paso ciego E2E."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8765) -> None:
        self.host = host
        self.port = port
        self._sessions: dict[str, RelaySession] = {}
        self._ws_to_role: dict[ServerConnection, tuple[str, str]] = {}
        self._server: Server | None = None

    @property
    def active_session_count(self) -> int:
        return len(self._sessions)

    async def start(self) -> None:
        self._server = await serve(
            self._handle_connection,
            self.host,
            self.port,
            max_size=MAX_MESSAGE_BYTES,
            ping_interval=20,
            ping_timeout=20,
            process_request=self._process_http_request,
        )
        # Actualiza el puerto real si se usó port=0 en pruebas
        if self._server.sockets:
            self.port = int(self._server.sockets[0].getsockname()[1])
        logger.info("Servidor Relay escuchando en ws://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._sessions.clear()
        self._ws_to_role.clear()

    async def serve_forever(self) -> None:
        await self.start()
        assert self._server is not None
        await self._server.serve_forever()

    async def _process_http_request(
        self,
        connection: ServerConnection,
        request: Any,
    ) -> Response | None:
        """Sirve /health y la Consola PWA para iPhone cuando no es un Upgrade WebSocket."""
        headers = getattr(request, "headers", None)
        upgrade = ""
        if headers is not None:
            try:
                upgrade = str(headers.get("Upgrade", "")).lower()
            except Exception:
                upgrade = ""
        if upgrade == "websocket":
            return None

        raw_path = str(getattr(request, "path", "/"))
        path = raw_path.split("?", 1)[0]

        if path in ("/health", "/healthz"):
            body = json.dumps(
                {"status": "ok", "sessions": len(self._sessions)}
            ).encode("utf-8")
            return Response(
                200,
                "OK",
                Headers([("Content-Type", "application/json")]),
                body,
            )

        mime = _STATIC_MIME.get(path)
        if mime is not None:
            filename = "index.html" if path == "/" else path.lstrip("/")
            file_path = _get_web_console_dir() / filename
            if file_path.is_file():
                try:
                    data = file_path.read_bytes()
                    return Response(
                        200,
                        "OK",
                        Headers(
                            [
                                ("Content-Type", mime),
                                ("Cache-Control", "no-cache"),
                            ]
                        ),
                        data,
                    )
                except OSError:
                    pass
        return None

    async def _send_json(self, ws: ServerConnection, payload: dict[str, Any]) -> None:
        try:
            await ws.send(json.dumps(payload, separators=(",", ":")))
        except ConnectionClosed:
            pass

    async def _handle_connection(self, ws: ServerConnection) -> None:
        try:
            async for message in ws:
                if isinstance(message, bytes):
                    await self._forward_binary(ws, message)
                else:
                    await self._handle_control_text(ws, message)
        except ConnectionClosed:
            pass
        except Exception as exc:
            logger.debug("Error en conexión relay: %s", exc)
        finally:
            await self._cleanup_connection(ws)

    async def _forward_binary(self, ws: ServerConnection, data: bytes) -> None:
        mapping = self._ws_to_role.get(ws)
        if not mapping:
            return
        session_id, role = mapping
        session = self._sessions.get(session_id)
        if not session:
            return
        target = session.client_ws if role == "host" else session.host_ws
        if target is None:
            return
        try:
            await target.send(data)
        except ConnectionClosed:
            pass

    async def _handle_control_text(self, ws: ServerConnection, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            await self._send_json(ws, {"type": "error", "message": "JSON inválido."})
            return

        msg_type = msg.get("type")

        if msg_type == "register_host":
            await self._on_register_host(ws, msg)
        elif msg_type == "request_challenge":
            await self._on_request_challenge(ws, msg)
        elif msg_type == "authenticate":
            await self._on_authenticate(ws, msg)
        elif msg_type == "disconnect_client":
            await self._on_host_kick_client(ws)
        elif msg_type == "ping":
            await self._send_json(ws, {"type": "pong"})
        else:
            await self._send_json(ws, {"type": "error", "message": f"Comando desconocido: {msg_type}"})

    async def _on_register_host(self, ws: ServerConnection, msg: dict[str, Any]) -> None:
        session_id = normalize_session_id(str(msg.get("session_id", "")))
        salt_b64 = str(msg.get("salt_b64", ""))
        auth_key_b64 = str(msg.get("auth_key_b64", ""))
        if not session_id or not salt_b64 or not auth_key_b64:
            await self._send_json(ws, {"type": "error", "message": "Datos de registro incompletos."})
            return

        existing = self._sessions.get(session_id)
        if existing is not None and existing.host_ws is not ws:
            await self._send_json(
                ws,
                {"type": "error", "message": "Este ID de sesión ya está en uso."},
            )
            return

        # Si el mismo host actualiza PIN o vuelve a registrarse
        if existing is not None and existing.client_ws is not None:
            await self._send_json(existing.client_ws, {"type": "peer_disconnected", "reason": "Host reiniciado"})
            self._ws_to_role.pop(existing.client_ws, None)

        self._sessions[session_id] = RelaySession(
            session_id=session_id,
            host_ws=ws,
            salt_b64=salt_b64,
            auth_key_b64=auth_key_b64,
        )
        self._ws_to_role[ws] = (session_id, "host")
        logger.info("Host registrado: %s", session_id)
        await self._send_json(ws, {"type": "registered", "session_id": session_id})

    async def _on_request_challenge(self, ws: ServerConnection, msg: dict[str, Any]) -> None:
        session_id = normalize_session_id(str(msg.get("session_id", "")))
        session = self._sessions.get(session_id)
        if session is None:
            await self._send_json(
                ws,
                {"type": "error", "message": "No se encontró ningún PC conectado con ese ID."},
            )
            return

        now = time.monotonic()
        if now < session.locked_until:
            wait_s = int(session.locked_until - now) + 1
            await self._send_json(
                ws,
                {"type": "error", "message": f"Demasiados intentos fallidos. Espera {wait_s} s."},
            )
            return

        if session.client_ws is not None:
            await self._send_json(
                ws,
                {"type": "error", "message": "Este equipo ya está siendo controlado por otro cliente."},
            )
            return

        nonce = os.urandom(16)
        session.pending_nonces[ws] = nonce
        await self._send_json(
            ws,
            {
                "type": "challenge",
                "session_id": session_id,
                "salt_b64": session.salt_b64,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            },
        )

    async def _on_authenticate(self, ws: ServerConnection, msg: dict[str, Any]) -> None:
        session_id = normalize_session_id(str(msg.get("session_id", "")))
        proof_b64 = str(msg.get("proof_b64", ""))
        session = self._sessions.get(session_id)
        if session is None:
            await self._send_json(ws, {"type": "error", "message": "Sesión no disponible."})
            return

        now = time.monotonic()
        if now < session.locked_until:
            wait_s = int(session.locked_until - now) + 1
            await self._send_json(
                ws,
                {"type": "error", "message": f"Demasiados intentos fallidos. Espera {wait_s} s."},
            )
            return

        nonce = session.pending_nonces.pop(ws, None)
        if nonce is None:
            await self._send_json(ws, {"type": "error", "message": "Desafío expirado. Reintenta."})
            return

        if session.client_ws is not None:
            await self._send_json(ws, {"type": "error", "message": "El equipo ya está ocupado."})
            return

        if not verify_auth_proof(session.auth_key_b64, nonce, proof_b64):
            session.failed_attempts += 1
            if session.failed_attempts >= MAX_FAILED_ATTEMPTS:
                session.locked_until = now + LOCKOUT_SECONDS
                session.failed_attempts = 0
                await self._send_json(
                    ws,
                    {"type": "error", "message": f"PIN incorrecto. Bloqueado {int(LOCKOUT_SECONDS)} s."},
                )
            else:
                remaining = MAX_FAILED_ATTEMPTS - session.failed_attempts
                await self._send_json(
                    ws,
                    {"type": "error", "message": f"PIN incorrecto ({remaining} intentos restantes)."},
                )
            return

        session.failed_attempts = 0
        session.client_ws = ws
        self._ws_to_role[ws] = (session_id, "client")
        logger.info("Cliente emparejado con sesión %s", session_id)

        await self._send_json(ws, {"type": "paired", "role": "client", "session_id": session_id})
        await self._send_json(session.host_ws, {"type": "paired", "role": "host", "session_id": session_id})

    async def _on_host_kick_client(self, ws: ServerConnection) -> None:
        mapping = self._ws_to_role.get(ws)
        if not mapping or mapping[1] != "host":
            return
        session = self._sessions.get(mapping[0])
        if session and session.client_ws is not None:
            client = session.client_ws
            session.client_ws = None
            self._ws_to_role.pop(client, None)
            await self._send_json(client, {"type": "peer_disconnected", "reason": "El host cerró la sesión."})
            try:
                await client.close()
            except Exception:
                pass

    async def _cleanup_connection(self, ws: ServerConnection) -> None:
        # Limpia cualquier desafío pendiente
        for session in self._sessions.values():
            session.pending_nonces.pop(ws, None)

        mapping = self._ws_to_role.pop(ws, None)
        if not mapping:
            return
        session_id, role = mapping
        session = self._sessions.get(session_id)
        if not session:
            return

        if role == "host":
            self._sessions.pop(session_id, None)
            logger.info("Host desconectado: %s", session_id)
            if session.client_ws is not None:
                client = session.client_ws
                self._ws_to_role.pop(client, None)
                await self._send_json(client, {"type": "peer_disconnected", "reason": "El equipo remoto se desconectó."})
                try:
                    await client.close()
                except Exception:
                    pass
        elif role == "client":
            if session.client_ws is ws:
                session.client_ws = None
                logger.info("Cliente desconectado de sesión %s", session_id)
                await self._send_json(
                    session.host_ws,
                    {"type": "peer_disconnected", "reason": "El cliente se desconectó."},
                )
