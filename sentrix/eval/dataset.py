"""Dataset and DatasetItem for evaluation."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DatasetItem:
    id: str
    input: Any
    expected_output: Any | None
    metadata: dict
    created_at: float = field(default_factory=time.time)


class Dataset:
    def __init__(self, name: str, description: str = "", db_path: str | None = None):
        self.id = str(uuid.uuid4())
        self.name = name
        self.description = description
        self.created_at = time.time()
        self._db_path = db_path
        self._items: list[DatasetItem] = []
        self._load_or_create()

    def _load_or_create(self) -> None:
        try:
            from sentrix.db import _q, get_conn
            rows = _q(
                "SELECT id, created_at FROM datasets WHERE name = ?",
                (self.name,), self._db_path
            )
            if rows:
                self.id = rows[0]["id"]
                self.created_at = rows[0]["created_at"]
                # Load items
                item_rows = _q(
                    "SELECT * FROM dataset_items WHERE dataset_id = ? ORDER BY created_at",
                    (self.id,), self._db_path
                )
                for r in item_rows:
                    meta = json.loads(r["metadata"]) if r["metadata"] else {}
                    inp = json.loads(r["input"]) if r["input"] else ""
                    exp = json.loads(r["expected_output"]) if r["expected_output"] else None
                    self._items.append(DatasetItem(
                        id=r["id"],
                        input=inp,
                        expected_output=exp,
                        metadata=meta,
                        created_at=r["created_at"],
                    ))
            else:
                conn = get_conn(self._db_path)
                with conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO datasets (id, name, description, created_at) VALUES (?, ?, ?, ?)",
                        (self.id, self.name, self.description, self.created_at),
                    )
                conn.close()
        except Exception:
            pass

    def add(
        self,
        input: Any,
        expected_output: Any | None = None,
        metadata: dict | None = None,
    ) -> DatasetItem:
        item = DatasetItem(
            id=str(uuid.uuid4()),
            input=input,
            expected_output=expected_output,
            metadata=metadata or {},
        )
        self._items.append(item)
        try:
            from sentrix.db import get_conn
            conn = get_conn(self._db_path)
            with conn:
                conn.execute(
                    """INSERT INTO dataset_items
                       (id, dataset_id, input, expected_output, metadata, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (item.id, self.id,
                     json.dumps(input),
                     json.dumps(expected_output) if expected_output is not None else None,
                     json.dumps(item.metadata),
                     item.created_at),
                )
            conn.close()
        except Exception:
            pass
        return item

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def __getitem__(self, idx: int) -> DatasetItem:
        return self._items[idx]

    def to_list(self) -> list[dict]:
        return [
            {
                "id": item.id,
                "input": item.input,
                "expected_output": item.expected_output,
                "metadata": item.metadata,
            }
            for item in self._items
        ]

    @classmethod
    def from_list(cls, name: str, items: list[dict]) -> "Dataset":
        ds = cls(name)
        for item in items:
            ds.add(
                input=item.get("input", ""),
                expected_output=item.get("expected_output"),
                metadata=item.get("metadata", {}),
            )
        return ds

    @classmethod
    def from_jsonl(cls, name: str, path: str) -> "Dataset":
        ds = cls(name)
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    item = json.loads(line)
                    ds.add(
                        input=item.get("input", ""),
                        expected_output=item.get("expected_output"),
                        metadata=item.get("metadata", {}),
                    )
        return ds
