"""Contract tests — run before shipping any module.

Asserts, after discovery, that every plugin obeys the naming/category contract,
subclasses Module correctly, and that every workflow step references a real
module.
"""
from __future__ import annotations

import re

import pytest

from core import registry
from core.config import Config
from core.module import Module
from core.workflows import load_workflows

NAME_RE = re.compile(r"^(red|blue|ml)\.[A-Za-z0-9_]+$")


@pytest.fixture(scope="module")
def modules():
    return registry.discover(force=True)


def test_discovery_finds_core_modules(modules):
    for name in ("red.recon_nmap", "blue.capture_tshark"):
        assert name in modules, f"{name} was not discovered"


def test_names_unique(modules):
    # registry keys are unique by construction; assert nothing collapsed.
    manifest_names = [cls.manifest.name for cls in modules.values()]
    assert len(manifest_names) == len(set(manifest_names))
    assert set(manifest_names) == set(modules.keys())


def test_name_pattern_and_category_prefix(modules):
    for name, cls in modules.items():
        assert NAME_RE.match(name), f"{name!r} must match role.modulename"
        role = name.split(".", 1)[0]
        assert cls.manifest.category == role, (
            f"{name}: category {cls.manifest.category!r} != prefix {role!r}"
        )
        assert cls.manifest.name == name, "manifest.name must equal registry key"


def test_subclasses_implement_contract(modules):
    for name, cls in modules.items():
        assert issubclass(cls, Module), f"{name} is not a Module subclass"
        # abstractmethods are implemented (else instantiation would fail)
        assert not getattr(cls, "__abstractmethods__", set()), (
            f"{name} leaves abstract methods unimplemented"
        )
        inst = cls()
        assert callable(inst.is_available)
        assert callable(inst.run)


def test_workflow_steps_reference_registered_modules(modules):
    cfg = Config()
    wfs = load_workflows(cfg)
    assert wfs, "no workflows loaded"
    for wf_name, wf in wfs.items():
        steps = wf.get("steps", []) if isinstance(wf, dict) else []
        for step in steps:
            assert step in modules, (
                f"workflow {wf_name!r} references unknown module {step!r}"
            )
