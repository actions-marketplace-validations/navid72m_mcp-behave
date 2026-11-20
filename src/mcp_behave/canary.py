"""Canary token management and detection for mcp-behave runtime monitoring (Milestone 2b)."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Iterable, List, Set


class CanaryManager:
    """Tracks active session canary tokens and detects canary leakage across requests and responses."""

    def __init__(self, initial_canaries: Iterable[str] | None = None) -> None:
        self._canaries: Set[str] = set()
        if initial_canaries:
            for c in initial_canaries:
                c_clean = c.strip()
                if c_clean:
                    self._canaries.add(c_clean)

    @property
    def canaries(self) -> Set[str]:
        return set(self._canaries)

    def generate_canary(self, prefix: str = "mcpb_canary_") -> str:
        """Generate and register a new random canary token."""
        token = f"{prefix}{uuid.uuid4().hex}"
        self._canaries.add(token)
        return token

    def register(self, token: str) -> None:
        """Register an existing canary token."""
        token_clean = token.strip()
        if token_clean:
            self._canaries.add(token_clean)

    def load_from_file(self, path: str | Path) -> int:
        """Load canary tokens from a file (one token per line). Returns count loaded."""
        p = Path(path)
        if not p.is_file():
            return 0
        count = 0
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                token = line.strip()
                if token and not token.startswith("#"):
                    self._canaries.add(token)
                    count += 1
        return count

    def find_canaries(self, text: str) -> List[str]:
        """Return list of any registered canary tokens found in text."""
        if not self._canaries or not text:
            return []
        matches: List[str] = []
        for canary in self._canaries:
            if canary in text:
                matches.append(canary)
        return matches

    def find_canaries_in_bytes(self, data: bytes) -> List[str]:
        """Fast byte-level check for registered canaries."""
        if not self._canaries or not data:
            return []
        matches: List[str] = []
        for canary in self._canaries:
            canary_bytes = canary.encode("utf-8")
            if canary_bytes in data:
                matches.append(canary)
        return matches
