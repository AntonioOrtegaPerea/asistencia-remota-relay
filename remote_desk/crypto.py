"""Cifrado de extremo a extremo (AES-256-GCM) y autenticación desafío-respuesta."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16
NONCE_SIZE = 12


@dataclass(frozen=True)
class SessionKeys:
    """Claves derivadas del PIN y salt.

    `auth_key` se comparte con el servidor relay para verificar clientes sin
    revelar el PIN ni `enc_key`. `enc_key` nunca sale del Host ni del Cliente,
    garantizando cifrado de extremo a extremo sobre el servidor relay.
    """

    salt: bytes
    auth_key: bytes
    enc_key: bytes

    @property
    def salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode("ascii")

    @property
    def auth_key_b64(self) -> str:
        return base64.b64encode(self.auth_key).decode("ascii")


def derive_session_keys(pin: str, salt: bytes | None = None) -> SessionKeys:
    """Deriva claves independientes de autenticación y cifrado E2E desde el PIN."""
    if not pin:
        raise ValueError("El PIN no puede estar vacío.")
    actual_salt = salt if salt is not None else os.urandom(SALT_SIZE)
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode("utf-8"),
        actual_salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    auth_key = hmac.new(master_key, b"winremotedesk-auth-v1", hashlib.sha256).digest()
    enc_key = hmac.new(master_key, b"winremotedesk-e2e-v1", hashlib.sha256).digest()
    return SessionKeys(salt=actual_salt, auth_key=auth_key, enc_key=enc_key)


def compute_auth_proof(auth_key: bytes, nonce: bytes) -> str:
    """Calcula la prueba HMAC-SHA256 sobre un desafío (nonce)."""
    digest = hmac.new(auth_key, nonce, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def verify_auth_proof(auth_key_b64: str, nonce: bytes, proof_b64: str) -> bool:
    """Verifica la prueba HMAC en tiempo constante."""
    try:
        auth_key = base64.b64decode(auth_key_b64.encode("ascii"))
        provided = base64.b64decode(proof_b64.encode("ascii"))
    except Exception:
        return False
    expected = hmac.new(auth_key, nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


class E2ECipher:
    """Cifrado autenticado AES-256-GCM con protección contra replay por secuencia."""

    def __init__(self, enc_key: bytes) -> None:
        self._aes = AESGCM(enc_key)
        self._send_seq = 0
        self._recv_seq = -1

    def encrypt(self, plaintext: bytes) -> bytes:
        seq = self._send_seq
        self._send_seq += 1
        nonce = os.urandom(NONCE_SIZE)
        aad = struct.pack(">Q", seq)
        ciphertext = self._aes.encrypt(nonce, plaintext, aad)
        return aad + nonce + ciphertext

    def decrypt(self, packet: bytes) -> bytes:
        header_len = 8 + NONCE_SIZE
        if len(packet) <= header_len + 16:
            raise ValueError("Paquete cifrado incompleto o corrupto.")
        aad = packet[:8]
        (seq,) = struct.unpack(">Q", aad)
        if seq <= self._recv_seq:
            raise ValueError("Secuencia fuera de orden o paquete repetido.")
        nonce = packet[8:header_len]
        ciphertext = packet[header_len:]
        plaintext = self._aes.decrypt(nonce, ciphertext, aad)
        self._recv_seq = seq
        return plaintext
