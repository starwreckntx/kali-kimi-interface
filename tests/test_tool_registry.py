#!/usr/bin/env python3
"""
Tests for Verifiable Tool Registry
"""

import json
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from tool_registry import (
    VerifiableToolRegistry, ToolVerif, _hash_binary, _find_binary,
    SCHEMA_NMAP, SCHEMA_URL_TARGET, SCHEMA_EMPTY
)


class TestRegistryInit:
    def test_registry_creates_all_tools(self):
        reg = VerifiableToolRegistry()
        assert len(reg.all_tools()) >= 150

    def test_registry_detects_installed(self):
        reg = VerifiableToolRegistry()
        installed = reg.installed_tools()
        assert len(installed) > 0

    def test_registry_has_categories(self):
        reg = VerifiableToolRegistry()
        cats = reg.categories()
        assert len(cats) == 14
        assert "Information Gathering" in cats
        assert "Web Applications" in cats


class TestBinaryHashing:
    def test_hash_existing_binary(self):
        path, installed, sha = _find_binary("python3")
        assert installed is True
        assert sha is not None
        assert len(sha) == 64

    def test_hash_nonexistent(self):
        path, installed, sha = _find_binary("nonexistent_tool_xyz")
        assert installed is False
        assert sha is None

    def test_hash_nmap(self):
        path, installed, sha = _find_binary("nmap")
        if installed:
            assert len(sha) == 64
            assert path.endswith("nmap")


class TestToolVerification:
    def test_verify_installed_tool(self):
        reg = VerifiableToolRegistry()
        result = reg.verify_tool("nmap")
        if result.get("installed"):
            assert result["verified"] is True
            assert result["tampered"] is False
            assert result["original_hash"] == result["current_hash"]

    def test_verify_nonexistent_tool(self):
        reg = VerifiableToolRegistry()
        result = reg.verify_tool("nonexistent_xyz")
        assert "error" in result or result.get("not_installed")

    def test_verify_all_clean(self):
        reg = VerifiableToolRegistry()
        results = reg.verify_all()
        tampered = [r for r in results if r.get("tampered")]
        assert len(tampered) == 0, f"Tampered tools: {[t['name'] for t in tampered]}"


class TestInputValidation:
    def test_nmap_valid_input(self):
        reg = VerifiableToolRegistry()
        errors = reg.validate_input("nmap", {"target": "192.168.1.1"})
        assert errors == []

    def test_nmap_missing_target(self):
        reg = VerifiableToolRegistry()
        errors = reg.validate_input("nmap", {})
        assert any("target" in e.lower() for e in errors)

    def test_nmap_with_scan_type(self):
        reg = VerifiableToolRegistry()
        errors = reg.validate_input("nmap", {"target": "10.0.0.1", "scan_type": "syn"})
        assert errors == []

    def test_nmap_invalid_scan_type(self):
        reg = VerifiableToolRegistry()
        errors = reg.validate_input("nmap", {"target": "10.0.0.1", "scan_type": "invalid"})
        assert any("enum" in e.lower() or "scan_type" in e for e in errors)

    def test_unknown_tool(self):
        reg = VerifiableToolRegistry()
        errors = reg.validate_input("fake_tool", {})
        assert len(errors) > 0


class TestToolSpecs:
    def test_nmap_spec(self):
        reg = VerifiableToolRegistry()
        spec = reg.get("nmap")
        assert spec is not None
        assert spec.category == "Information Gathering"
        assert spec.permission == "danger-full-access"
        assert spec.parser == "nmap_xml"
        assert "target" in spec.input_schema.get("properties", {})

    def test_sqlmap_spec(self):
        reg = VerifiableToolRegistry()
        spec = reg.get("sqlmap")
        assert spec is not None
        assert spec.category == "Vulnerability Analysis"
        assert "url" in spec.input_schema.get("properties", {})

    def test_hydra_spec(self):
        reg = VerifiableToolRegistry()
        spec = reg.get("hydra")
        assert spec is not None
        assert spec.permission == "danger-full-access"
        assert spec.parser == "hydra"
        assert "target" in spec.input_schema.get("properties", {})
        assert "service" in spec.input_schema.get("properties", {})


class TestIntegrityReport:
    def test_report_structure(self):
        reg = VerifiableToolRegistry()
        report = reg.integrity_report()
        assert "total_tools" in report
        assert "installed" in report
        assert "verified_clean" in report
        assert "tampered" in report
        assert "categories" in report
        assert "verification_details" in report

    def test_report_consistency(self):
        reg = VerifiableToolRegistry()
        report = reg.integrity_report()
        assert report["verified_clean"] == report["installed"]
        assert report["tampered"] == 0


class TestManifest:
    def test_save_manifest(self, tmp_path):
        reg = VerifiableToolRegistry()
        path = str(tmp_path / "test_manifest.json")
        reg.save_manifest(path)
        
        with open(path) as f:
            manifest = json.load(f)
        
        assert "generated_at" in manifest
        assert manifest["total_tools"] >= 150
        assert "tools" in manifest
        assert "integrity_report" in manifest
        assert len(manifest["tools"]) == manifest["total_tools"]


class TestSerialization:
    def test_to_dict(self):
        reg = VerifiableToolRegistry()
        spec = reg.get("nmap")
        d = spec.to_dict()
        assert d["name"] == "nmap"
        assert "sha256" in d
        assert "input_schema" in d

    def test_to_json_roundtrip(self):
        reg = VerifiableToolRegistry()
        spec = reg.get("nmap")
        j = spec.to_json()
        parsed = json.loads(j)
        assert parsed["name"] == "nmap"

    def test_registry_to_json(self):
        reg = VerifiableToolRegistry()
        j = reg.to_json(installed_only=True)
        parsed = json.loads(j)
        assert len(parsed) > 0
        for name, tool_data in parsed.items():
            assert tool_data["installed"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
