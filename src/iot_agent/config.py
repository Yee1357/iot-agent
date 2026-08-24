"""Configuration management for IoT Agent."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env relative to project root, not CWD
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_prefix="IOT_AGENT_",
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- IDA Pro ---
    ida_install_dir: str = ""

    # --- Linux VM (optional remote execution) ---
    vm_ssh_host: str = ""
    vm_ssh_port: int = 22
    vm_ssh_user: str = ""
    vm_ssh_password: str = ""
    vm_ssh_key_path: str = ""
    vm_firmware_dir: str = "/data/firmware"
    #: Chroot runtime assets (libnvram shim) for single-service
    #: dynamic verification. Full-system emulation assets were removed.
    vm_runtime_dir: str = "/data/runtime-assets"
    #: Optional GitHub download mirror (e.g. "https://ghproxy.net/") for
    #: regions where github.com release downloads are slow. Empty = direct.
    download_mirror: str = ""

    # --- Logging ---
    log_level: str = "INFO"

    @property
    def vm_configured(self) -> bool:
        return bool(self.vm_ssh_host and self.vm_ssh_user)


# Global singleton
settings = Settings()


def ensure_idalib_config() -> None:
    """Write ida-install-dir to the Hex-Rays config file if missing or empty.

    The idalib SDK reads this config on import. If ida-install-dir is empty,
    os.add_dll_directory("") fails with error 87.
    """
    if not settings.ida_install_dir:
        return

    import json
    import platform

    config_path = None
    if platform.system() == "Windows":
        config_path = Path(os.getenv("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    else:
        config_path = Path.home() / ".idapro" / "ida-config.json"

    if config_path is None:
        return

    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    current = config.get("Paths", {}).get("ida-install-dir", "")
    if current and Path(current).exists():
        return  # already valid

    config.setdefault("Paths", {})["ida-install-dir"] = settings.ida_install_dir
    config_path.write_text(json.dumps(config, indent=4))
