"""Shared test fixtures: mock httpx.AsyncClient so no test touches the real network."""

from __future__ import annotations

from typing import Callable

import httpx
import pytest


@pytest.fixture
def patch_client(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable], None]:
    """Route every httpx.AsyncClient created during the test through `handler`."""

    def _patch(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        real_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            real_init(self, *args, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    return _patch
