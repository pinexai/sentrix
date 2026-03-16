"""Supply chain & RAG security — scan for poisoned documents and prompt tampering."""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field


# Patterns that indicate injected instructions in documents
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(your|all)\s+(previous\s+)?instructions?",
    r"system\s+override",
    r"new\s+instructions?:",
    r"forget\s+(everything|all)\s+(above|previous)",
    r"<\s*admin[_\s]override",
    r"\[\s*inject",
    r"you\s+are\s+now\s+(a|an|the)\s+\w+\s+(ai|bot|assistant)",
    r"act\s+as\s+(a|an)\s+unrestricted",
    r"safety\s+(mode|filter|guidelines?)\s*(=\s*false|disabled|off)",
    r"dan\s+mode",
    r"jailbreak",
]

# PII patterns
_PII_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "phone": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

_compiled_injection = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]
_compiled_pii = {k: re.compile(v) for k, v in _PII_PATTERNS.items()}


@dataclass
class RAGScanReport:
    documents_scanned: int
    poisoned_documents: list[dict]
    prompt_template_issues: list[str]
    pii_documents: list[dict]
    system_prompt_hash: str | None
    hash_mismatch: bool
    total_cost_usd: float = 0.0
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def summary(self) -> None:
        print(f"\n[pyntrace] RAG Security Scan Report")
        print(f"  Documents scanned    : {self.documents_scanned}")
        print(f"  Poisoned documents   : {len(self.poisoned_documents)}")
        print(f"  PII documents        : {len(self.pii_documents)}")
        print(f"  Prompt issues        : {len(self.prompt_template_issues)}")
        print(f"  System prompt hash   : {self.system_prompt_hash or 'N/A'}")
        print(f"  Hash mismatch        : {'YES ⚠️' if self.hash_mismatch else 'No'}")

        if self.poisoned_documents:
            print("\n  Poisoned documents:")
            for doc in self.poisoned_documents[:5]:
                print(f"    [{doc['poison_type']}] {doc['content_snippet'][:80]}...")

        if self.pii_documents:
            print("\n  Documents with PII:")
            for doc in self.pii_documents[:5]:
                types = ", ".join(doc["pii_types"])
                print(f"    [{types}] Doc #{doc['doc_index']}")

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "documents_scanned": self.documents_scanned,
            "poisoned_documents": self.poisoned_documents,
            "pii_documents": self.pii_documents,
            "prompt_template_issues": self.prompt_template_issues,
            "system_prompt_hash": self.system_prompt_hash,
            "hash_mismatch": self.hash_mismatch,
            "total_cost_usd": self.total_cost_usd,
            "created_at": self.created_at,
        }

    def _persist(self) -> None:
        try:
            from pyntrace.db import get_conn
            conn = get_conn()
            d = self.to_json()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO rag_scan_reports
                       (id, documents_scanned, poisoned_count, system_prompt_hash, results_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (self.id, d["documents_scanned"], len(d["poisoned_documents"]),
                     d["system_prompt_hash"], json.dumps(d), self.created_at),
                )
            conn.close()
        except Exception as e:
            print(f"[pyntrace] Warning: could not persist RAG report: {e}")


def scan_rag(
    documents: list[str] | list[dict],
    system_prompt: str | None = None,
    check_injection: bool = True,
    check_pii: bool = True,
    verify_prompt_integrity: bool = True,
    baseline_hash: str | None = None,
    _persist: bool = True,
) -> RAGScanReport:
    """
    Scan a RAG document corpus for security issues.

    No LLM calls required — uses regex and pattern matching.

    Args:
        documents: list of strings or dicts (with 'content' key)
        system_prompt: system prompt to hash for integrity checking
        check_injection: scan for injected instructions
        check_pii: scan for PII in documents
        verify_prompt_integrity: compute + compare system prompt hash
        baseline_hash: expected SHA256 of system prompt (tamper detection)
        _persist: write results to SQLite

    Returns:
        RAGScanReport with poisoned docs, PII docs, and prompt integrity status
    """
    poisoned_documents = []
    pii_documents = []
    prompt_template_issues = []

    print(f"[pyntrace] Scanning {len(documents)} documents for security issues...")

    for i, doc in enumerate(documents):
        # Normalize to string
        if isinstance(doc, dict):
            content = doc.get("content", doc.get("text", doc.get("page_content", str(doc))))
        else:
            content = str(doc)

        doc_id = doc.get("id", f"doc_{i}") if isinstance(doc, dict) else f"doc_{i}"

        # Check for injected instructions
        if check_injection:
            for pattern in _compiled_injection:
                match = pattern.search(content)
                if match:
                    snippet = content[max(0, match.start() - 30):match.end() + 50]
                    poisoned_documents.append({
                        "doc_index": i,
                        "doc_id": doc_id,
                        "poison_type": "instruction_injection",
                        "pattern": pattern.pattern[:50],
                        "content_snippet": snippet,
                    })
                    break  # One report per document

        # Check for PII
        if check_pii:
            found_pii = []
            for pii_type, pattern in _compiled_pii.items():
                if pattern.search(content):
                    found_pii.append(pii_type)
            if found_pii:
                pii_documents.append({
                    "doc_index": i,
                    "doc_id": doc_id,
                    "pii_types": found_pii,
                })

    # Check system prompt integrity
    system_prompt_hash = None
    hash_mismatch = False

    if verify_prompt_integrity and system_prompt:
        system_prompt_hash = hashlib.sha256(system_prompt.encode()).hexdigest()
        if baseline_hash and baseline_hash != system_prompt_hash:
            hash_mismatch = True
            prompt_template_issues.append(
                f"System prompt hash mismatch! Expected {baseline_hash[:16]}..., got {system_prompt_hash[:16]}..."
            )

        # Store baseline if not set
        if not baseline_hash:
            _store_baseline_hash(system_prompt_hash)

    print(f"  Found {len(poisoned_documents)} poisoned, {len(pii_documents)} with PII")

    report = RAGScanReport(
        documents_scanned=len(documents),
        poisoned_documents=poisoned_documents,
        pii_documents=pii_documents,
        prompt_template_issues=prompt_template_issues,
        system_prompt_hash=system_prompt_hash,
        hash_mismatch=hash_mismatch,
    )

    if _persist:
        report._persist()

    return report


def _store_baseline_hash(hash_val: str) -> None:
    try:
        from pyntrace.db import get_conn
        conn = get_conn()
        with conn:
            conn.execute(
                "INSERT INTO rag_scan_reports (id, documents_scanned, poisoned_count, system_prompt_hash, results_json, created_at) VALUES (?, 0, 0, ?, '{}', ?)",
                (str(uuid.uuid4()), hash_val, time.time()),
            )
        conn.close()
    except Exception:
        pass
