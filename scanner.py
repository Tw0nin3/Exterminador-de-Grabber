"""Inspeção conservadora de scripts de inicialização do Discord."""
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone

MAX_SIZE = 10 * 1024 * 1024
RULES = {
    "acesso a token": re.compile(rb"(?:localStorage\s*\.\s*getItem\s*\(\s*[\"\']token[\"\']|(?:grab|steal)[_ ]?token|dQw4w9WgXcQ:)", re.I),
    "envio para webhook": re.compile(rb"discord(?:app)?\.com/api(?:/v\d+)?/webhooks/", re.I),
    "execução de código codificado": re.compile(rb"(?:eval\s*\(\s*atob\s*\(|eval\s*\(\s*Buffer\.from\s*\()", re.I),
    "interceptação de requisições": re.compile(rb"(?:webRequest\.onBeforeRequest|webRequest\.onCompleted)", re.I),
}

@dataclass
class Finding:
    path: str
    sha256: str
    reasons: list[str]
    risk: str

@dataclass
class ScanResult:
    roots: list[str]
    findings: list[Finding]
    errors: list[str]
    files_scanned: int
    cancelled: bool = False
    def as_dict(self):
        return asdict(self)

def discover_roots():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        return []
    return [Path(base) / name for name in ("Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment") if (Path(base) / name).is_dir()]

def scan(roots, cancelled=lambda: False, progress=lambda _: None):
    findings, errors, seen = [], [], set()
    count = 0
    core_count = 0
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            errors.append(f"Pasta indisponível: {root}")
            continue
        # Os módulos discord_desktop_core ficam dentro de app-*/modules.
        for app in root.glob("app-*"):
            if cancelled():
                return ScanResult([str(r) for r in roots], findings, errors, count, True)
            modules = app / "modules"
            try:
                cores = list(modules.glob("discord_desktop_core-*/discord_desktop_core"))
            except OSError as e:
                errors.append(f"{modules}: {e}")
                continue
            for core in cores:
                core_count += 1
                def onerror(e):
                    errors.append(str(e))
                for directory, dirs, files in os.walk(core, followlinks=False, onerror=onerror):
                    dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink() and d.lower() not in {"node_modules", "cache"}]
                    for name in files:
                        if cancelled():
                            return ScanResult([str(r) for r in roots], findings, errors, count, True)
                        path = Path(directory) / name
                        if path.suffix.lower() not in {".js", ".cjs", ".mjs"} or path.is_symlink():
                            continue
                        key = os.path.normcase(str(path.resolve()))
                        if key in seen:
                            continue
                        seen.add(key)
                        try:
                            if path.stat().st_size > MAX_SIZE:
                                errors.append(f"Arquivo maior que 10 MiB, ignorado: {path}")
                                continue
                            data = path.read_bytes()
                            count += 1
                            progress(str(path))
                            reasons = [label for label, pattern in RULES.items() if pattern.search(data)]
                            if reasons:
                                risk = "ALTO" if "acesso a token" in reasons and ("envio para webhook" in reasons or "interceptação de requisições" in reasons) else "ATENÇÃO"
                                findings.append(Finding(str(path), hashlib.sha256(data).hexdigest(), reasons, risk))
                        except OSError as e:
                            errors.append(f"{path}: {e}")
    if roots and core_count == 0:
        errors.append("Nenhum módulo discord_desktop_core encontrado nas pastas selecionadas.")
    return ScanResult([str(r) for r in roots], findings, errors, count)

def quarantine(finding, destination):
    """Copia e verifica antes de remover, recusando arquivo modificado ou link."""
    source = Path(finding.path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("O arquivo não existe ou é um link.")
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != finding.sha256:
        raise ValueError("O arquivo mudou desde a varredura; execute outra varredura.")
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    ident = uuid.uuid4().hex
    backup = dest / (ident + ".bin")
    metadata = dest / (ident + ".json")
    with backup.open("xb") as f:
        f.write(data)
    metadata.write_text(json.dumps({"original": str(source.resolve()), "sha256": finding.sha256, "backup": backup.name, "date": datetime.now(timezone.utc).isoformat()}, ensure_ascii=False, indent=2), encoding="utf-8")
    if hashlib.sha256(source.read_bytes()).hexdigest() != finding.sha256 or source.is_symlink():
        raise ValueError("O arquivo mudou durante a operação; cópia preservada na quarentena.")
    source.unlink()
    return metadata

def restore(metadata):
    metadata = Path(metadata)
    info = json.loads(metadata.read_text(encoding="utf-8"))
    backup = metadata.parent / info["backup"]
    target = Path(info["original"])
    data = backup.read_bytes()
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise ValueError("A cópia de quarentena não passou na verificação SHA-256.")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as f:
        f.write(data)
    return target
