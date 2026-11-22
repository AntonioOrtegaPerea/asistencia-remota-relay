"""Persistencia de configuración local, valores por defecto y utilidades de red."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_RELAY_PORT = 8765
DEFAULT_DIRECT_PORT = 8766
DEFAULT_RELAY_URL = "wss://asistencia-remota-antonio-ortega.onrender.com"
DEFAULT_FIXED_PASSWORD = "AntonioOrtega@"


def get_app_data_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        base = Path(appdata) / "AsistenciaRemotaAntonioOrtega"
        legacy = Path(appdata) / "WinRemoteDesk"
    else:
        base = Path.home() / ".asistenciaremota_ao"
        legacy = Path.home() / ".winremotedesk"

    base.mkdir(parents=True, exist_ok=True)
    # Migra agenda/configuración previa si existía de la versión anterior
    if legacy.exists():
        for fname in ("peers.json", "console_config.json", "host_config.json"):
            src = legacy / fname
            dst = base / fname
            if src.exists() and not dst.exists():
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    pass
    return base


def get_config_path(filename: str = "config.json") -> Path:
    return get_app_data_dir() / filename


def get_received_files_dir() -> Path:
    """Carpeta donde el Agente Remoto guarda los archivos enviados desde la Consola."""
    home = Path.home()
    for candidate in (home / "Desktop", home / "Escritorio", home / "Downloads", home):
        if candidate.exists():
            dest = candidate / "Archivos Recibidos - Asistencia Remota"
            try:
                dest.mkdir(parents=True, exist_ok=True)
                return dest
            except OSError:
                continue
    fallback = get_app_data_dir() / "ArchivosRecibidos"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def generate_session_id() -> str:
    """Genera un ID numérico legible de 9 dígitos (formato XXX-XXX-XXX)."""
    digits = "".join(str(secrets.randbelow(10)) for _ in range(9))
    return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"


def normalize_session_id(raw: str) -> str:
    """Normaliza un ID eliminando espacios y guiones."""
    cleaned = "".join(ch for ch in raw.strip() if ch.isalnum()).upper()
    if len(cleaned) == 9 and cleaned.isdigit():
        return f"{cleaned[:3]}-{cleaned[3:6]}-{cleaned[6:]}"
    return cleaned


def normalize_relay_url(raw: str) -> str:
    """Normaliza una URL de Relay (acepta https://, http://, wss://, ws:// o dominio directo)."""
    url = raw.strip().rstrip("/")
    if not url:
        return ""
    low = url.lower()
    if low.startswith("https://"):
        url = "wss://" + url[8:]
    elif low.startswith("http://"):
        url = "ws://" + url[7:]
    elif not low.startswith(("wss://", "ws://")):
        # Si es IP local o localhost usa ws://; si es dominio en Internet usa wss://
        host_part = url.split("/", 1)[0].split(":", 1)[0].lower()
        if host_part in ("localhost", "127.0.0.1") or host_part.startswith(("192.168.", "10.", "172.")):
            url = "ws://" + url
        else:
            url = "wss://" + url
    return url


def generate_pin(length: int = 6) -> str:
    """Genera un PIN aleatorio seguro."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def get_local_ip() -> str:
    """Obtiene la IP local preferida de la máquina en la LAN."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


@dataclass
class AppConfig:
    relay_url: str = DEFAULT_RELAY_URL
    session_id: str = ""
    host_mode: str = "relay"  # "relay" | "direct"
    direct_port: int = DEFAULT_DIRECT_PORT
    quality: int = 65
    scale: float = 0.85
    fps: int = 20
    monitor: int = 1
    allow_control: bool = True
    # Acceso desatendido (Agente Remoto): por defecto siempre activo con contraseña fija
    use_fixed_password: bool = True
    fixed_password_enc: str = ""
    auto_start_service: bool = True
    # Consola de Control
    last_target_id: str = ""
    last_direct_address: str = ""
    local_relay_port: int = DEFAULT_RELAY_PORT

    def ensure_defaults(self) -> None:
        if not self.session_id:
            self.session_id = generate_session_id()


def load_config(filename: str = "config.json") -> AppConfig:
    path = get_config_path(filename)
    cfg = AppConfig()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for key, value in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, value)
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    # Actualiza automáticamente configuraciones antiguas que apuntaban solo a localhost
    if not cfg.relay_url or cfg.relay_url.strip().rstrip("/") in ("ws://127.0.0.1:8765", "ws://localhost:8765"):
        cfg.relay_url = DEFAULT_RELAY_URL
    cfg.ensure_defaults()
    return cfg


def save_config(cfg: AppConfig, filename: str = "config.json") -> None:
    path = get_config_path(filename)
    try:
        path.write_text(
            json.dumps(asdict(cfg), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass
