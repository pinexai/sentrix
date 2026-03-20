"""Tests for pyntrace.guard.model_audit — no real model files needed."""
from __future__ import annotations

import io
import json
import pickle
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from pyntrace.guard.model_audit import (
    ModelAuditReport,
    ModelFinding,
    audit_model,
    audit_models,
    _detect_format,
    _scan_pickle,
    _scan_pytorch,
    _scan_hdf5,
    _scan_onnx,
    _scan_safetensors,
    _scan_numpy,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_tmp(data: bytes, suffix: str) -> Path:
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(data)
        return Path(f.name)


def _make_malicious_pickle() -> bytes:
    """Craft a pickle stream that references os.system."""
    import pickle, io
    # We don't actually create a payload that executes; we just craft
    # the byte pattern that the scanner looks for: b"os\nsystem"
    buf = io.BytesIO()
    buf.write(b"\x80\x05")           # pickle protocol 5 header
    buf.write(b"os\nsystem\n")       # the pattern the scanner detects
    buf.write(b"q\x00.")             # minimal pickle tail
    return buf.getvalue()


def _make_benign_pickle() -> bytes:
    """A real pickle that the scanner should flag only as LOW risk."""
    return pickle.dumps({"weights": [1.0, 2.0, 3.0], "bias": 0.5})


def _make_safetensors(header_dict: dict, tensor_data: bytes = b"\x00" * 16) -> bytes:
    header_bytes = json.dumps(header_dict).encode("utf-8")
    header_len = struct.pack("<Q", len(header_bytes))
    return header_len + header_bytes + tensor_data


# ── Format detection ──────────────────────────────────────────────────────────

class TestFormatDetection:
    def test_pickle_magic_v4(self):
        p = Path("model.pkl")
        assert _detect_format(p, b"\x80\x04rest") == "pickle"

    def test_pickle_magic_v5(self):
        p = Path("model.pkl")
        assert _detect_format(p, b"\x80\x05rest") == "pickle"

    def test_pytorch_zip(self):
        p = Path("model.pt")
        assert _detect_format(p, b"PK\x03\x04rest") == "pytorch"

    def test_hdf5_magic(self):
        p = Path("model.h5")
        assert _detect_format(p, b"\x89HDF") == "hdf5"

    def test_numpy_magic(self):
        p = Path("model.npy")
        assert _detect_format(p, b"\x93NUMPY") == "numpy"

    def test_safetensors_by_extension(self):
        p = Path("model.safetensors")
        data = struct.pack("<Q", 2) + b"{}" + b"\x00" * 8
        assert _detect_format(p, data) == "safetensors"

    def test_unknown_extension(self):
        p = Path("model.bin")
        assert _detect_format(p, b"\x00\x01\x02") == "unknown"


# ── Pickle scanner ────────────────────────────────────────────────────────────

class TestPickleScanner:
    def test_detects_os_system(self):
        p = Path("model.pkl")
        data = b"\x80\x04os\nsystem\nR."
        findings = _scan_pickle(p, data)
        severities = {f.severity for f in findings}
        assert CRITICAL in severities

    def test_detects_subprocess(self):
        p = Path("model.pkl")
        data = b"\x80\x04subprocess\nPopen\nR."
        findings = _scan_pickle(p, data)
        assert any(f.severity == CRITICAL for f in findings)

    def test_benign_pickle_gets_low_warning(self):
        p = Path("model.pkl")
        data = _make_benign_pickle()
        findings = _scan_pickle(p, data)
        assert any(f.rule_id == "PICKLE002" for f in findings)
        assert all(f.severity in (LOW, INFO) for f in findings)

    def test_eval_detected_as_critical(self):
        p = Path("model.pkl")
        data = b"\x80\x04builtins\neval\nR."
        findings = _scan_pickle(p, data)
        assert any(f.severity == CRITICAL for f in findings)


# ── PyTorch scanner ───────────────────────────────────────────────────────────

class TestPyTorchScanner:
    def _make_pytorch_zip(self, pkl_data: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", pkl_data)
        return buf.getvalue()

    def test_benign_pytorch(self):
        p = Path("model.pt")
        pkl = _make_benign_pickle()
        data = self._make_pytorch_zip(pkl)
        findings = _scan_pytorch(p, data)
        # Should only have MEDIUM "PyTorch checkpoint contains pickle" at most
        assert all(f.severity in (MEDIUM, LOW, INFO) for f in findings)

    def test_malicious_pytorch(self):
        p = Path("model.pt")
        pkl = _make_malicious_pickle()
        data = self._make_pytorch_zip(pkl)
        findings = _scan_pytorch(p, data)
        severities = {f.severity for f in findings}
        assert CRITICAL in severities or HIGH in severities


# ── HDF5 scanner ──────────────────────────────────────────────────────────────

class TestHDF5Scanner:
    def test_lambda_layer_detected(self):
        p = Path("model.h5")
        data = b"\x89HDF\x00" + b"Lambda" + b"\x00" * 100
        findings = _scan_hdf5(p, data)
        assert any(f.rule_id == "HDF5001" for f in findings)
        assert any(f.severity == HIGH for f in findings)

    def test_embedded_pickle_detected(self):
        p = Path("model.h5")
        data = b"\x89HDF\x00" + b"\x80\x04" + b"\x00" * 100
        findings = _scan_hdf5(p, data)
        assert any(f.rule_id == "HDF5002" for f in findings)

    def test_clean_hdf5_gets_low(self):
        p = Path("model.h5")
        data = b"\x89HDF\x00" + b"\x00" * 200
        findings = _scan_hdf5(p, data)
        assert all(f.severity in (LOW, INFO) for f in findings)


# ── ONNX scanner ──────────────────────────────────────────────────────────────

class TestONNXScanner:
    def test_custom_op_detected(self):
        p = Path("model.onnx")
        data = b"onnx_header" + b"PythonOp" + b"\x00" * 50
        findings = _scan_onnx(p, data)
        assert any(f.rule_id == "ONNX001" for f in findings)

    def test_clean_onnx_gets_info(self):
        p = Path("model.onnx")
        data = b"onnx_standard_ops_only\x00" * 10
        findings = _scan_onnx(p, data)
        assert any(f.severity == INFO for f in findings)


# ── safetensors scanner ───────────────────────────────────────────────────────

class TestSafetensorsScanner:
    def test_valid_clean(self):
        p = Path("model.safetensors")
        data = _make_safetensors({"__metadata__": {"model": "test"}, "weight": {}})
        findings = _scan_safetensors(p, data)
        assert any(f.rule_id == "ST006" for f in findings)
        assert all(f.severity == INFO for f in findings)

    def test_too_small(self):
        p = Path("model.safetensors")
        findings = _scan_safetensors(p, b"\x00\x01")
        assert any(f.rule_id == "ST001" for f in findings)

    def test_abnormal_header_size(self):
        p = Path("model.safetensors")
        data = struct.pack("<Q", 200 * 1024 * 1024) + b"{}" + b"\x00" * 8
        findings = _scan_safetensors(p, data)
        assert any(f.rule_id == "ST002" for f in findings)

    def test_suspicious_metadata_key(self):
        p = Path("model.safetensors")
        data = _make_safetensors({"__metadata__": {"exec_command": "rm -rf /"}})
        findings = _scan_safetensors(p, data)
        assert any(f.rule_id == "ST004" for f in findings)

    def test_invalid_json_header(self):
        p = Path("model.safetensors")
        bad_json = b"NOT_VALID_JSON{"
        header_len = struct.pack("<Q", len(bad_json))
        data = header_len + bad_json + b"\x00" * 16
        findings = _scan_safetensors(p, data)
        assert any(f.rule_id == "ST005" for f in findings)


# ── NumPy scanner ─────────────────────────────────────────────────────────────

class TestNumpyScanner:
    def test_object_dtype_flagged(self):
        p = Path("data.npy")
        # Craft minimal .npy header with object dtype
        header_str = "{'descr': '|O', 'fortran_order': False, 'shape': (3,), }"
        header_bytes = header_str.encode("latin-1")
        padding = b" " * (64 - len(header_bytes) - 1) + b"\n"
        header = header_bytes + padding
        magic = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header))
        data = magic + header + b"\x00" * 24
        findings = _scan_numpy(p, data)
        assert any(f.rule_id == "NPY002" for f in findings)


# ── Full audit_model API ──────────────────────────────────────────────────────

class TestAuditModel:
    def test_audit_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            audit_model("/nonexistent/path/model.pkl")

    def test_audit_directory_raises(self, tmp_path):
        with pytest.raises(IsADirectoryError):
            audit_model(str(tmp_path))

    def test_audit_benign_pickle(self, tmp_path):
        f = tmp_path / "model.pkl"
        f.write_bytes(_make_benign_pickle())
        report = audit_model(str(f))
        assert isinstance(report, ModelAuditReport)
        assert report.format == "pickle"
        assert report.file_size_bytes > 0
        assert len(report.sha256) == 64
        assert len(report.findings) > 0  # at least the LOW warning

    def test_audit_malicious_pickle(self, tmp_path):
        f = tmp_path / "bad.pkl"
        f.write_bytes(_make_malicious_pickle())
        report = audit_model(str(f))
        assert not report.safe

    def test_audit_safetensors_clean(self, tmp_path):
        f = tmp_path / "model.safetensors"
        f.write_bytes(_make_safetensors({"__metadata__": {}, "weight": {}}))
        report = audit_model(str(f))
        assert report.format == "safetensors"
        assert report.safe  # INFO findings don't make it unsafe

    def test_to_json_serializable(self, tmp_path):
        f = tmp_path / "model.pkl"
        f.write_bytes(_make_benign_pickle())
        report = audit_model(str(f))
        data = report.to_json()
        assert isinstance(data, dict)
        assert "findings" in data
        assert isinstance(data["findings"], list)
        # Should be JSON-serializable
        json.dumps(data)

    def test_audit_models_directory(self, tmp_path):
        (tmp_path / "a.pkl").write_bytes(_make_benign_pickle())
        (tmp_path / "b.pkl").write_bytes(_make_benign_pickle())
        reports = audit_models(str(tmp_path))
        assert len(reports) == 2
        assert all(isinstance(r, ModelAuditReport) for r in reports)


# ── Secret scanner ────────────────────────────────────────────────────────────

class TestSecretScanner:
    def test_api_key_in_model(self, tmp_path):
        f = tmp_path / "model.pkl"
        data = _make_benign_pickle() + b"sk-" + b"x" * 50
        f.write_bytes(data)
        report = audit_model(str(f))
        rule_ids = {finding.rule_id for finding in report.findings}
        assert "SEC001" in rule_ids

    def test_private_key_in_model(self, tmp_path):
        f = tmp_path / "model.pkl"
        data = _make_benign_pickle() + b"-----BEGIN RSA PRIVATE KEY-----\n"
        f.write_bytes(data)
        report = audit_model(str(f))
        rule_ids = {finding.rule_id for finding in report.findings}
        assert "SEC004" in rule_ids
        assert any(f.severity == CRITICAL for f in report.findings if f.rule_id == "SEC004")


# ── ModelAuditReport ─────────────────────────────────────────────────────────

class TestModelAuditReport:
    def _make_report(self, findings):
        return ModelAuditReport(
            path="/tmp/test.pkl",
            file_size_bytes=1024,
            sha256="a" * 64,
            format="pickle",
            findings=findings,
        )

    def test_safe_when_no_critical_or_high(self):
        report = self._make_report([
            ModelFinding(LOW, "LOW001", "Low issue", "desc", "/tmp/t.pkl"),
        ])
        assert report.safe

    def test_not_safe_with_critical(self):
        report = self._make_report([
            ModelFinding(CRITICAL, "MAL001", "Critical", "desc", "/tmp/t.pkl"),
        ])
        assert not report.safe

    def test_not_safe_with_high(self):
        report = self._make_report([
            ModelFinding(HIGH, "MAL010", "High", "desc", "/tmp/t.pkl"),
        ])
        assert not report.safe

    def test_sarif_output(self, tmp_path):
        report = self._make_report([
            ModelFinding(HIGH, "MAL001", "Bad", "desc", "/tmp/t.pkl"),
        ])
        sarif_path = tmp_path / "out.sarif"
        report.save_sarif(str(sarif_path))
        data = json.loads(sarif_path.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1
