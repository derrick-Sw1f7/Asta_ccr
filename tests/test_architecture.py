"""Executable guardrails for boundaries, pure safety paths, and design artifacts.

These checks examine dependencies and contracts rather than reproduce scoring
or compression algorithms. Behavioral tests remain in their owning modules.
"""
from __future__ import annotations

import ast
from dataclasses import is_dataclass
import io
import json
from pathlib import Path
import re
import sys
import tokenize
from typing import get_type_hints, is_typeddict

import pytest

from ccr import contracts


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "ccr"
MODULE_PATHS = {path.stem: path for path in SOURCE.glob("*.py")}

# This is the architecture's permission graph, not a snapshot of current imports.
# Edges point toward dependencies; only the outer application imports I/O adapters.
ALLOWED_DEPENDENCIES = {
    "__init__": set(),
    "__main__": {"cli"},
    "contracts": set(),
    "config": {"contracts"},
    "integrity": {"contracts", "ingestion"},
    "ingestion": {"contracts"},
    "segmentation": {"contracts"},
    "scoring": {"contracts", "config"},
    "compression": {"contracts", "config", "integrity", "ingestion", "scoring"},
    "proof": {"__init__", "contracts", "config", "integrity", "ingestion", "segmentation", "scoring", "compression"},
    "replay": {"__init__", "contracts", "config", "integrity", "ingestion", "segmentation", "scoring", "compression", "proof"},
    "adapters": {"contracts", "integrity"},
    "app": {"contracts", "config", "integrity", "ingestion", "segmentation", "scoring", "compression", "proof", "replay", "adapters", "demo"},
    "demo": {"contracts"},
    "cli": {"app", "adapters", "demo", "ingestion", "replay", "integrity", "config", "contracts"},
}

PURE_MODULES = ("config", "integrity", "ingestion", "segmentation", "scoring", "compression", "proof")
FORBIDDEN_IO_IMPORTS = {
    "os", "sys", "pathlib", "io", "socket", "subprocess", "http", "urllib",
    "logging", "time", "asyncio", "smtplib", "tempfile", "shutil", "glob",
    "multiprocessing", "threading", "importlib",
}
FORBIDDEN_DIRECT_CALLS = {
    "open", "print", "input", "__import__", "eval", "exec",
    "getenv", "read", "readline", "readlines", "read_text", "read_bytes",
    "write", "writelines", "write_text", "write_bytes", "dump", "load",
    "mkdir", "unlink", "urlopen", "request", "send", "recv", "getLogger",
    "debug", "info", "warning", "error", "critical", "exception", "log",
    "now", "utcnow", "today", "time", "perf_counter", "monotonic", "sleep",
}


def parse_module(name: str) -> ast.Module:
    return ast.parse(MODULE_PATHS[name].read_text(encoding="utf-8"), filename=str(MODULE_PATHS[name]))


def import_module(node: ast.ImportFrom) -> str:
    """Resolve this flat package's relative imports without importing code."""
    if node.level:
        assert node.level == 1, "CCR modules may not escape the package with relative imports"
        return "ccr" + (f".{node.module}" if node.module else "")
    return node.module or ""


def project_dependency(module: str) -> str | None:
    if module == "ccr":
        return "__init__"
    if module.startswith("ccr."):
        parts = module.split(".")
        assert len(parts) == 2, "The architecture has no private nested subpackages"
        return parts[1]
    return None


def module_imports(tree: ast.Module) -> list[str]:
    result = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = import_module(node)
            if module == "ccr":
                result.extend(f"ccr.{alias.name}" if alias.name in MODULE_PATHS else module for alias in node.names)
            else:
                result.append(module)
    return result


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def test_declared_modules_have_explicit_dependency_boundaries():
    assert set(MODULE_PATHS) == set(ALLOWED_DEPENDENCIES)


@pytest.mark.parametrize("name", sorted(MODULE_PATHS))
def test_actual_imports_obey_public_dependency_graph(name):
    dependencies = {project_dependency(module) for module in module_imports(parse_module(name))}
    dependencies.discard(None)
    assert dependencies <= ALLOWED_DEPENDENCIES[name], f"{name} imports outside its boundary: {dependencies - ALLOWED_DEPENDENCIES[name]}"


def test_actual_dependency_graph_has_no_cycles():
    graph = {
        name: {dependency for module in module_imports(parse_module(name)) if (dependency := project_dependency(module)) is not None}
        for name in MODULE_PATHS
    }
    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        assert name not in active, f"cyclic module dependency reaches {name}"
        if name in visited:
            return
        active.add(name)
        for dependency in graph[name]:
            assert dependency in graph, f"undeclared package module {dependency}"
            visit(dependency)
        active.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)


@pytest.mark.parametrize("name", sorted(MODULE_PATHS))
def test_no_cross_module_private_imports_or_access(name):
    tree = parse_module(name)
    imported_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "ccr" or alias.name.startswith("ccr."):
                    imported_names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else "ccr"
        elif isinstance(node, ast.ImportFrom):
            module = import_module(node)
            if project_dependency(module) is not None:
                for alias in node.names:
                    assert alias.name != "*", "Wildcard imports conceal module boundaries"
                    public_version = module == "ccr" and alias.name == "__version__"
                    assert not alias.name.startswith("_") or public_version, f"{name} imports private {module}.{alias.name}"
                    imported_names[alias.asname or alias.name] = f"{module}.{alias.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            path = dotted_name(node)
            if path is None:
                continue
            root, *attributes = path.split(".")
            if root in imported_names:
                resolved = ".".join([imported_names[root], *attributes])
                private_parts = [part for part in resolved.split(".")[1:] if part.startswith("_")]
                assert not private_parts or resolved == "ccr.__version__", f"{name} accesses private boundary {resolved}"


@pytest.mark.parametrize("name", sorted(MODULE_PATHS))
def test_runtime_package_imports_only_python_standard_library(name):
    for module in module_imports(parse_module(name)):
        root = module.split(".")[0]
        assert root == "ccr" or root in sys.stdlib_module_names, f"{name} adds runtime dependency {module}"


@pytest.mark.parametrize("name", PURE_MODULES)
def test_safety_core_has_no_direct_io_logging_environment_or_clock_access(name):
    tree = parse_module(name)
    imports = module_imports(tree)
    assert not {module.split(".")[0] for module in imports} & FORBIDDEN_IO_IMPORTS
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bindings[alias.asname or alias.name] = f"{import_module(node)}.{alias.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call = dotted_name(node.func)
            if call:
                root, *attributes = call.split(".")
                resolved = ".".join([bindings.get(root, root), *attributes])
                assert resolved.split(".")[-1] not in FORBIDDEN_DIRECT_CALLS, f"{name} performs direct side effect {resolved}"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "environ", f"{name} reads process environment"
    # datetime.fromisoformat is pure calendar validation; actual clock methods
    # (now/utcnow/today) are forbidden above even if datetime is aliased.


@pytest.mark.parametrize("path", sorted([*MODULE_PATHS.values(), *(ROOT / "tests").glob("test_*.py")]), ids=lambda path: path.name)
def test_all_python_files_accept_python_310_grammar(path):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))


def test_all_contract_classes_and_fields_have_resolvable_types_and_documentation():
    text = (SOURCE / "contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    comment_lines = {
        token.start[0]: token.string.lstrip("# ").strip()
        for token in tokenize.generate_tokens(io.StringIO(text).readline)
        if token.type == tokenize.COMMENT
    }
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    assert classes, "Boundary contracts must be declared explicitly"
    for node in classes:
        assert ast.get_docstring(node), f"{node.name} lacks a contract docstring"
        fields = [field for field in node.body if isinstance(field, ast.AnnAssign)]
        runtime_type = getattr(contracts, node.name)
        assert is_dataclass(runtime_type) or is_typeddict(runtime_type) or any(
            isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases
        ), f"{node.name} must use a dataclass, TypedDict, or injected Protocol"
        hints = get_type_hints(runtime_type)
        assert fields, f"{node.name} must declare its boundary data"
        for field in fields:
            assert isinstance(field.target, ast.Name)
            assert field.target.id in hints, f"{node.name}.{field.target.id} has an unresolved type"
            assert comment_lines.get(field.end_lineno), f"{node.name}.{field.target.id} lacks field documentation"
        assert not [field for field in node.body if isinstance(field, ast.Assign)], f"{node.name} has an untyped field"
        for method in [item for item in node.body if isinstance(item, ast.FunctionDef)]:
            assert ast.get_docstring(method), f"{node.name}.{method.name} lacks interface documentation"
            assert method.returns is not None
            assert all(argument.annotation is not None for argument in method.args.args if argument.arg != "self")


def test_design_contract_block_matches_actual_public_interfaces():
    document = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- CONTRACTS_START -->\s*```python\n(.*?)\n```\s*<!-- CONTRACTS_END -->", document, re.DOTALL)
    assert match, "Architecture must include the complete fenced public contracts"
    assert match.group(1).strip() == (SOURCE / "contracts.py").read_text(encoding="utf-8").strip()


def test_proof_schema_is_self_contained_and_requires_audit_evidence():
    schema = json.loads((ROOT / "docs" / "proof.schema.json").read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert {"segment_id", "events", "kept", "merged", "dropped", "token_estimation", "generated_at", "ccr_version", "scorer"} <= set(schema["required"])
    definitions = schema["$defs"]
    assert {"safety_tags", "content_sha256"} <= set(definitions["proofDropped"]["required"])
    assert "source_segment_ids" in definitions["proofMerged"]["required"]
    assert definitions["proofMerged"]["properties"]["source_segment_ids"]["minItems"] >= 2
    assert definitions["sha256"]["minLength"] == definitions["sha256"]["maxLength"] == 64

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            if "$ref" in value:
                reference = value["$ref"]
                assert isinstance(reference, str) and reference.startswith("#/"), "Schema must not need network references"
                resolved = schema
                for component in reference[2:].split("/"):
                    resolved = resolved[component.replace("~1", "/").replace("~0", "~")]
                assert isinstance(resolved, dict), f"Unresolved schema reference {reference}"
            if value.get("type") == "object" and "properties" in value:
                assert value.get("additionalProperties") is False, "Contract objects must reject unknown fields"
                assert set(value.get("required", [])) <= set(value["properties"])
            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect(schema)
