"""ModelAudit — scan saved ML model files for security vulnerabilities.

Supported formats
─────────────────
  .pkl / .pickle   Python pickle — arbitrary code execution via __reduce__
  .pt / .pth       PyTorch — can embed pickle payloads
  .joblib          joblib / sklearn — pickle-based
  .h5 / .hdf5      Keras/HDF5 — inspect for suspicious Lambda layers
  .onnx            ONNX — inspect for untrusted custom ops
  .safetensors     safetensors — safe by design, but verify header size
  .npy / .npz      NumPy — allow_pickle bypass detection

Usage
─────
    from pyntrace.guard.model_audit import audit_model
    report = audit_model("./model.pkl")
    report.summary()   # prints CRITICAL / HIGH / MEDIUM findings
    report.to_json()   # serializable dict

CLI
───
    pyntrace audit-model ./model.pkl
    pyntrace audit-model ./models/ --format json
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Finding severity tiers ────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

_SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}


@dataclass
class ModelFinding:
    severity: str
    rule_id: str
    title: str
    description: str
    file_path: str
    offset: int = -1
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "offset": self.offset,
            "evidence": self.evidence,
        }


@dataclass
class ModelAuditReport:
    path: str
    file_size_bytes: int
    sha256: str
    format: str
    findings: list[ModelFinding] = field(default_factory=list)
    scan_duration_s: float = 0.0
    scanned_at: float = field(default_factory=time.time)

    # ── Derived properties ─────────────────────────────────────────────────────

    @property
    def critical(self) -> list[ModelFinding]:
        return [f for f in self.findings if f.severity == CRITICAL]

    @property
    def high(self) -> list[ModelFinding]:
        return [f for f in self.findings if f.severity == HIGH]

    @property
    def safe(self) -> bool:
        return len(self.critical) == 0 and len(self.high) == 0

    # ── Output ─────────────────────────────────────────────────────────────────

    def summary(self) -> None:
        _SEV_COLOR = {
            CRITICAL: "\033[91m",
            HIGH: "\033[93m",
            MEDIUM: "\033[94m",
            LOW: "\033[96m",
            INFO: "\033[37m",
        }
        RESET = "\033[0m"
        BOLD = "\033[1m"

        print(f"\n{BOLD}ModelAudit — {self.path}{RESET}")
        print(f"  Format : {self.format}  |  Size: {self.file_size_bytes:,} bytes")
        print(f"  SHA256 : {self.sha256[:16]}…")
        print(f"  Scanned: {len(self.findings)} finding(s) in {self.scan_duration_s:.2f}s\n")

        if not self.findings:
            print(f"  {_SEV_COLOR[INFO]}✓ No security issues found.{RESET}\n")
            return

        for f in sorted(self.findings, key=lambda x: _SEVERITY_ORDER.get(x.severity, 0), reverse=True):
            color = _SEV_COLOR.get(f.severity, "")
            print(f"  {color}[{f.severity}]{RESET} {f.title}")
            print(f"         Rule : {f.rule_id}")
            print(f"         {f.description}")
            if f.evidence:
                print(f"         Evidence: {f.evidence[:120]}")
            print()

    def to_json(self) -> dict:
        return {
            "path": self.path,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "format": self.format,
            "findings": [f.to_dict() for f in self.findings],
            "critical_count": len(self.critical),
            "high_count": len(self.high),
            "safe": self.safe,
            "scan_duration_s": self.scan_duration_s,
            "scanned_at": self.scanned_at,
        }

    def save_sarif(self, output_path: str) -> None:
        """Export findings as SARIF 2.1.0 for GitHub Advanced Security."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "pyntrace-model-audit", "version": "0.6.0",
                                    "rules": []}},
                "results": [],
            }],
        }
        run = sarif["runs"][0]
        for finding in self.findings:
            run["tool"]["driver"]["rules"].append({  # type: ignore[union-attr]
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.description},
                "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            })
            run["results"].append({  # type: ignore[union-attr]
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file_path}}}],
            })
        with open(output_path, "w") as fh:
            json.dump(sarif, fh, indent=2)


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "INFO": "none"}.get(severity, "none")


# ── Public API ────────────────────────────────────────────────────────────────

def audit_model(path: str) -> ModelAuditReport:
    """Scan a single model file and return a :class:`ModelAuditReport`."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Model file not found: {path}")
    if p.is_dir():
        raise IsADirectoryError(f"Use audit_models() for directories: {path}")

    start = time.time()
    data = p.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    fmt = _detect_format(p, data)
    findings = _scan(p, data, fmt)
    duration = time.time() - start

    return ModelAuditReport(
        path=str(p.resolve()),
        file_size_bytes=len(data),
        sha256=sha256,
        format=fmt,
        findings=findings,
        scan_duration_s=duration,
    )


def audit_models(directory: str, recursive: bool = True) -> list[ModelAuditReport]:
    """Scan all model files in a directory."""
    d = Path(directory)
    if not d.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    extensions = {".pkl", ".pickle", ".pt", ".pth", ".joblib", ".h5", ".hdf5",
                  ".onnx", ".safetensors", ".npy", ".npz"}
    glob = d.rglob("*") if recursive else d.glob("*")
    files = [f for f in glob if f.is_file() and f.suffix.lower() in extensions]

    return [audit_model(str(f)) for f in sorted(files)]


# ── Format detection ──────────────────────────────────────────────────────────

def _detect_format(p: Path, data: bytes) -> str:
    ext = p.suffix.lower()
    magic_map = {
        b"\x80\x02": "pickle",  # pickle protocol 2
        b"\x80\x03": "pickle",  # pickle protocol 3
        b"\x80\x04": "pickle",  # pickle protocol 4
        b"\x80\x05": "pickle",  # pickle protocol 5
        b"PK\x03\x04": "zip",   # ZIP (PyTorch .pt often uses ZIP)
        b"\x89HDF": "hdf5",
        b"\x93NUMPY": "numpy",
    }
    for magic, fmt in magic_map.items():
        if data[:len(magic)] == magic:
            if fmt == "zip" and ext in (".pt", ".pth"):
                return "pytorch"
            return fmt

    ext_map = {
        ".pkl": "pickle", ".pickle": "pickle",
        ".pt": "pytorch", ".pth": "pytorch",
        ".joblib": "joblib",
        ".h5": "hdf5", ".hdf5": "hdf5",
        ".onnx": "onnx",
        ".safetensors": "safetensors",
        ".npy": "numpy", ".npz": "numpy",
    }
    return ext_map.get(ext, "unknown")


# ── Scanner dispatch ──────────────────────────────────────────────────────────

def _scan(p: Path, data: bytes, fmt: str) -> list[ModelFinding]:
    scanners = {
        "pickle": _scan_pickle,
        "pytorch": _scan_pytorch,
        "joblib": _scan_joblib,
        "hdf5": _scan_hdf5,
        "onnx": _scan_onnx,
        "safetensors": _scan_safetensors,
        "numpy": _scan_numpy,
    }
    scanner = scanners.get(fmt, _scan_generic)
    findings = scanner(p, data)
    # Always run the generic secret-pattern scan on top
    findings += _scan_secrets(p, data)
    return findings


# ── Pickle scanner ────────────────────────────────────────────────────────────

# Opcodes that indicate code execution when unpickling
_PICKLE_EXEC_OPCODES = {
    b"R": "REDUCE (calls a callable with args — arbitrary code execution)",
    b"i": "INST (creates instance — can call __reduce__)",
    b"o": "OBJ (creates object via callable)",
    b"b": "BUILD (calls __setstate__ — can trigger code)",
    b"\x81": "NEWOBJ (calls __new__ — can trigger code)",
    b"\x82": "EXT1",
    b"\x83": "EXT2",
    b"\x84": "EXT4",
    b"\x93": "STACK_GLOBAL (loads arbitrary module attribute)",
}

# Known dangerous module/class combos in pickle streams
_DANGEROUS_PICKLE_PATTERNS = [
    (b"os\nsystem", CRITICAL, "MAL001", "OS command execution via os.system"),
    (b"subprocess\nPopen", CRITICAL, "MAL002", "Subprocess execution via subprocess.Popen"),
    (b"subprocess\ncall", CRITICAL, "MAL003", "Subprocess execution via subprocess.call"),
    (b"subprocess\ncheck_output", CRITICAL, "MAL004", "Subprocess via check_output"),
    (b"builtins\nexec", CRITICAL, "MAL005", "Arbitrary code via exec()"),
    (b"builtins\neval", CRITICAL, "MAL006", "Arbitrary code via eval()"),
    (b"__builtin__\nexec", CRITICAL, "MAL005", "Arbitrary code via exec() (Py2)"),
    (b"builtins\ncompile", HIGH, "MAL007", "Dynamic code compilation via compile()"),
    (b"importlib\nimport_module", HIGH, "MAL008", "Dynamic module import"),
    (b"ctypes\nCDLL", CRITICAL, "MAL009", "Native library loading via ctypes"),
    (b"socket\nsocket", HIGH, "MAL010", "Socket creation — possible exfiltration"),
    (b"urllib\nrequest", HIGH, "MAL011", "HTTP request — possible exfiltration"),
    (b"requests\nget", HIGH, "MAL012", "HTTP GET via requests — possible exfiltration"),
    (b"shutil\nrmtree", HIGH, "MAL013", "Recursive file deletion via shutil.rmtree"),
    (b"os\nremove", MEDIUM, "MAL014", "File deletion via os.remove"),
    (b"tempfile\nNamedTemporaryFile", LOW, "MAL015", "Temporary file creation"),
]


def _scan_pickle(p: Path, data: bytes, label: str = "pickle") -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    path_str = str(p)

    # Dangerous pattern search
    for pattern, severity, rule_id, description in _DANGEROUS_PICKLE_PATTERNS:
        idx = data.find(pattern)
        if idx != -1:
            evidence = data[max(0, idx - 20): idx + len(pattern) + 20]
            findings.append(ModelFinding(
                severity=severity,
                rule_id=rule_id,
                title=f"Dangerous pickle payload: {description}",
                description=(
                    f"The {label} file contains a reference to {description}. "
                    "Loading this file with pickle.load() will execute this code."
                ),
                file_path=path_str,
                offset=idx,
                evidence=repr(evidence),
            ))

    # Check for REDUCE opcode — hallmark of code execution payloads
    reduce_count = data.count(b"R")
    if reduce_count > 0 and any(p in data for p in (b"os\n", b"subprocess\n", b"builtins\n")):
        findings.append(ModelFinding(
            severity=HIGH,
            rule_id="PICKLE001",
            title="Pickle REDUCE opcode with suspicious module references",
            description=(
                f"Found {reduce_count} REDUCE opcode(s) combined with suspicious module imports. "
                "This is the standard pattern for malicious pickle payloads."
            ),
            file_path=path_str,
        ))

    # Warn that ANY pickle is inherently unsafe to load from untrusted sources
    if not findings:
        findings.append(ModelFinding(
            severity=LOW,
            rule_id="PICKLE002",
            title="Pickle format — inherently unsafe from untrusted sources",
            description=(
                "Pickle files can execute arbitrary code when loaded. "
                "Only load this file if you trust the source completely. "
                "Consider migrating to safetensors for safe model storage."
            ),
            file_path=path_str,
        ))

    return findings


def _scan_pytorch(p: Path, data: bytes) -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    path_str = str(p)

    # PyTorch ZIP: check each contained pickle stream
    if data[:4] == b"PK\x03\x04":
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if name.endswith(".pkl") or "data.pkl" in name:
                        pkl_data = zf.read(name)
                        inner = _scan_pickle(p, pkl_data, label=f"PyTorch/{name}")
                        # Elevate LOW "inherently unsafe" to MEDIUM for PyTorch
                        for f in inner:
                            if f.rule_id == "PICKLE002":
                                f.severity = MEDIUM
                                f.title = "PyTorch checkpoint contains pickle — verify source"
                        findings.extend(inner)
        except Exception:
            pass
    else:
        # Legacy PyTorch format (older .pt files are raw pickle)
        findings.extend(_scan_pickle(p, data, label="PyTorch (legacy pickle)"))

    return findings


def _scan_joblib(p: Path, data: bytes) -> list[ModelFinding]:
    # joblib is pickle-based; scan as pickle but add a joblib-specific note
    findings = _scan_pickle(p, data, label="joblib")
    for f in findings:
        if f.rule_id == "PICKLE002":
            f.description = (
                "joblib uses pickle internally. "
                "Only load sklearn/joblib files from trusted sources. "
                "Consider using ONNX or safetensors for safer deployment."
            )
    return findings


# ── HDF5 / Keras scanner ──────────────────────────────────────────────────────

def _scan_hdf5(p: Path, data: bytes) -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    path_str = str(p)

    # Keras Lambda layers contain serialized Python bytecode
    if b"lambda" in data.lower() or b"Lambda" in data:
        findings.append(ModelFinding(
            severity=HIGH,
            rule_id="HDF5001",
            title="Keras Lambda layer detected — contains serialized Python code",
            description=(
                "HDF5/Keras models with Lambda layers serialize Python bytecode. "
                "Loading this model executes the embedded code. "
                "Verify the model source and consider replacing Lambda layers."
            ),
            file_path=path_str,
        ))

    # Check for pickle references inside HDF5
    if b"pickle" in data or b"\x80\x04" in data or b"\x80\x05" in data:
        findings.append(ModelFinding(
            severity=MEDIUM,
            rule_id="HDF5002",
            title="Pickle data embedded in HDF5 file",
            description=(
                "The HDF5 file contains embedded pickle data which can execute code on load."
            ),
            file_path=path_str,
        ))

    if not findings:
        findings.append(ModelFinding(
            severity=LOW,
            rule_id="HDF5003",
            title="HDF5/Keras model — verify source",
            description="No obvious malicious patterns found. Always load models from trusted sources.",
            file_path=path_str,
        ))

    return findings


# ── ONNX scanner ──────────────────────────────────────────────────────────────

_ONNX_SUSPICIOUS_OPS = [
    b"PythonOp", b"CustomOp", b"com.microsoft.PythonOp",
    b"TorchScript", b"ScriptModule",
]


def _scan_onnx(p: Path, data: bytes) -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    path_str = str(p)

    for op in _ONNX_SUSPICIOUS_OPS:
        if op in data:
            findings.append(ModelFinding(
                severity=HIGH,
                rule_id="ONNX001",
                title=f"Suspicious custom op in ONNX model: {op.decode(errors='replace')}",
                description=(
                    "ONNX models with custom operators can execute arbitrary code "
                    "when the operator is loaded. Verify this operator is from a trusted source."
                ),
                file_path=path_str,
                evidence=op.decode(errors="replace"),
            ))

    # Check for embedded pickle
    if b"\x80\x04" in data or b"\x80\x05" in data:
        findings.append(ModelFinding(
            severity=MEDIUM,
            rule_id="ONNX002",
            title="Pickle payload embedded in ONNX file",
            description="Embedded pickle data found inside ONNX model. This may execute code on load.",
            file_path=path_str,
        ))

    if not findings:
        findings.append(ModelFinding(
            severity=INFO,
            rule_id="ONNX003",
            title="ONNX model — no suspicious ops detected",
            description="No known dangerous patterns found. ONNX is generally safer than pickle formats.",
            file_path=path_str,
        ))

    return findings


# ── safetensors scanner ───────────────────────────────────────────────────────

def _scan_safetensors(p: Path, data: bytes) -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    path_str = str(p)

    # safetensors format: first 8 bytes = header length (little-endian uint64)
    if len(data) < 8:
        findings.append(ModelFinding(
            severity=HIGH, rule_id="ST001",
            title="safetensors file too small — possible truncation or corruption",
            description="File is less than 8 bytes and cannot be a valid safetensors file.",
            file_path=path_str,
        ))
        return findings

    header_len = struct.unpack("<Q", data[:8])[0]
    if header_len > 100 * 1024 * 1024:  # 100 MB header is suspicious
        findings.append(ModelFinding(
            severity=HIGH, rule_id="ST002",
            title="Abnormally large safetensors header",
            description=(
                f"Header claims to be {header_len:,} bytes. "
                "This may indicate a zip-bomb or header manipulation attack."
            ),
            file_path=path_str,
        ))
        return findings

    if len(data) < 8 + header_len:
        findings.append(ModelFinding(
            severity=MEDIUM, rule_id="ST003",
            title="safetensors header length exceeds file size",
            description="Header length field exceeds available data — file may be corrupt.",
            file_path=path_str,
        ))
        return findings

    # Try parsing the JSON header
    try:
        header_bytes = data[8: 8 + header_len]
        header = json.loads(header_bytes.decode("utf-8"))
        # Check for __metadata__ with suspicious keys
        metadata = header.get("__metadata__", {})
        suspicious_keys = [k for k in metadata if any(
            kw in k.lower() for kw in ("exec", "eval", "pickle", "code", "script")
        )]
        if suspicious_keys:
            findings.append(ModelFinding(
                severity=MEDIUM, rule_id="ST004",
                title="Suspicious metadata keys in safetensors header",
                description=f"Metadata contains potentially suspicious keys: {suspicious_keys}",
                file_path=path_str,
                evidence=str(suspicious_keys),
            ))
    except (json.JSONDecodeError, UnicodeDecodeError):
        findings.append(ModelFinding(
            severity=MEDIUM, rule_id="ST005",
            title="safetensors header is not valid JSON",
            description="The header could not be parsed as JSON — file may be corrupt or malformed.",
            file_path=path_str,
        ))

    if not findings:
        findings.append(ModelFinding(
            severity=INFO, rule_id="ST006",
            title="safetensors — safe format, no issues detected",
            description="safetensors does not support code execution. This is the recommended format.",
            file_path=path_str,
        ))

    return findings


# ── NumPy scanner ─────────────────────────────────────────────────────────────

def _scan_numpy(p: Path, data: bytes) -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    path_str = str(p)

    # NPZ files are ZIP archives — check for allow_pickle markers
    if data[:4] == b"PK\x03\x04":
        if b"allow_pickle" in data or b"pickle" in data.lower():
            findings.append(ModelFinding(
                severity=MEDIUM, rule_id="NPY001",
                title="NumPy archive may require allow_pickle=True",
                description=(
                    "This .npz file appears to contain object arrays or pickle data. "
                    "Loading with allow_pickle=True enables arbitrary code execution."
                ),
                file_path=path_str,
            ))

    # Raw .npy with object dtype header
    if data[:6] == b"\x93NUMPY":
        # Header is a Python literal dict; scan for object dtype
        header_end = data.find(b"\n", 10)
        header_str = data[10:header_end].decode("latin-1", errors="replace")
        if "'O'" in header_str or "|O" in header_str or "object" in header_str:
            findings.append(ModelFinding(
                severity=MEDIUM, rule_id="NPY002",
                title="NumPy array with object dtype — unsafe without allow_pickle=False",
                description=(
                    "Object dtype arrays require pickling. "
                    "Loading with allow_pickle=True can execute arbitrary code."
                ),
                file_path=path_str,
                evidence=header_str[:100],
            ))

    if not findings:
        findings.append(ModelFinding(
            severity=INFO, rule_id="NPY003",
            title="NumPy file — no obvious unsafe patterns",
            description="No object dtype or pickle markers found.",
            file_path=path_str,
        ))

    return findings


# ── Generic / secret scanner ──────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[bytes, str, str, str]] = [
    (b"sk-", HIGH, "SEC001", "Possible OpenAI API key embedded in model file"),
    (b"AKIA", HIGH, "SEC002", "Possible AWS Access Key ID embedded in model file"),
    (b"ghp_", HIGH, "SEC003", "Possible GitHub Personal Access Token in model file"),
    (b"-----BEGIN RSA PRIVATE KEY-----", CRITICAL, "SEC004", "RSA private key embedded in model file"),
    (b"-----BEGIN EC PRIVATE KEY-----", CRITICAL, "SEC005", "EC private key embedded in model file"),
    (b"-----BEGIN PRIVATE KEY-----", CRITICAL, "SEC006", "Private key embedded in model file"),
    (b"password", MEDIUM, "SEC007", "String 'password' found in model file"),
    (b"secret", MEDIUM, "SEC008", "String 'secret' found in model file"),
]


def _scan_secrets(p: Path, data: bytes) -> list[ModelFinding]:
    findings: list[ModelFinding] = []
    for pattern, severity, rule_id, description in _SECRET_PATTERNS:
        idx = data.lower().find(pattern.lower())
        if idx != -1:
            evidence = data[max(0, idx - 5): idx + len(pattern) + 20]
            findings.append(ModelFinding(
                severity=severity,
                rule_id=rule_id,
                title=description,
                description=(
                    f"The model file contains the string '{pattern.decode(errors='replace')}' "
                    "which may indicate embedded credentials or private keys."
                ),
                file_path=str(p),
                offset=idx,
                evidence=repr(evidence),
            ))
    return findings


def _scan_generic(p: Path, data: bytes) -> list[ModelFinding]:
    return [ModelFinding(
        severity=LOW,
        rule_id="GEN001",
        title="Unknown file format — limited analysis performed",
        description=f"File extension '{p.suffix}' is not a recognized ML model format. "
                    "Only secret pattern scanning was performed.",
        file_path=str(p),
    )]
