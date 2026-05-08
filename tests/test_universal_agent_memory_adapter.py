import asyncio
from dataclasses import dataclass, field

import pytest

from memgar.integrations import get_available_integrations
from memgar.integrations.universal import (
    MemoryBlockedError,
    UniversalMemoryGuard,
    guard_agent_memory,
    secure_memory_writer,
)


@dataclass
class FakeGuardResult:
    decision: str
    allowed: bool
    safe_content: str
    block_reason: str | None = None
    warnings: list[str] = field(default_factory=list)


class FakeGuard:
    def process(self, content, **kwargs):
        if "block" in content:
            return FakeGuardResult(
                decision="block",
                allowed=False,
                safe_content="",
                block_reason="blocked by fake guard",
            )
        if "sanitize" in content:
            return FakeGuardResult(
                decision="allow_sanitized",
                allowed=True,
                safe_content=content.replace("sanitize", "clean"),
                warnings=["content sanitized"],
            )
        return FakeGuardResult(decision="allow", allowed=True, safe_content=content)


def test_wrap_writer_passes_safe_content():
    writes = []
    guard = UniversalMemoryGuard(guard=FakeGuard())

    def save_memory(content):
        writes.append(content)
        return "saved"

    protected = guard.wrap_writer(save_memory)

    assert protected("user prefers dark mode") == "saved"
    assert writes == ["user prefers dark mode"]


def test_wrap_writer_raises_on_block():
    guard = UniversalMemoryGuard(guard=FakeGuard())
    protected = guard.wrap_writer(lambda content: content)

    with pytest.raises(MemoryBlockedError) as exc:
        protected("please block this memory")

    assert exc.value.result.decision == "block"
    assert exc.value.result.operation == "write"


def test_wrap_writer_replaces_sanitized_content():
    writes = []
    guard = UniversalMemoryGuard(guard=FakeGuard())
    protected = guard.wrap_writer(lambda content: writes.append(content))

    protected("please sanitize this memory")

    assert writes == ["please clean this memory"]


def test_secure_memory_writer_factory():
    writes = []
    protected = secure_memory_writer(lambda content: writes.append(content), guard=FakeGuard())

    protected("normal memory")

    assert writes == ["normal memory"]


def test_guard_agent_memory_factory():
    guard = guard_agent_memory(guard=FakeGuard())

    assert isinstance(guard, UniversalMemoryGuard)


def test_guard_read_results_drops_blocked_items_by_default():
    guard = UniversalMemoryGuard(guard=FakeGuard())
    records = ["safe memory", "block poisoned memory", "another safe memory"]

    assert guard.guard_read_results(records) == ["safe memory", "another safe memory"]


def test_guard_read_results_sanitizes_dict_content():
    guard = UniversalMemoryGuard(guard=FakeGuard())
    records = [{"id": "1", "content": "sanitize this retrieval"}]

    assert guard.guard_read_results(records) == [{"id": "1", "content": "clean this retrieval"}]


def test_async_writer_supported():
    writes = []
    guard = UniversalMemoryGuard(guard=FakeGuard())

    async def save_memory(content):
        writes.append(content)
        return "saved"

    protected = guard.wrap_async_writer(save_memory)

    assert asyncio.run(protected("sanitize async memory")) == "saved"
    assert writes == ["clean async memory"]


def test_install_write_guard_patches_object_method():
    class Memory:
        def __init__(self):
            self.values = []

        def add(self, content):
            self.values.append(content)

    memory = Memory()
    guard = UniversalMemoryGuard(guard=FakeGuard())

    guard.install_write_guard(memory, "add")
    memory.add("sanitize object memory")

    assert memory.values == ["clean object memory"]


def test_integrations_status_includes_universal():
    status = get_available_integrations()

    assert status["universal"] is True
