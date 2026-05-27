"""
Regression tests: finding description, remediation, and proof must be
redacted before being written to the findings table.

redact_dict() already existed in redaction.py but was never called on
findings before storage. These tests verify it is now called on both
insert paths: _upsert_findings_and_report and
_upsert_findings_and_report_from_scanner.
"""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.secuscan.redaction import redact_dict


# ---------------------------------------------------------------------------
# Unit: redact_dict handles finding shapes correctly
# ---------------------------------------------------------------------------

def test_redact_dict_redacts_aws_key_in_description():
    finding = {
        "title": "Open Port",
        "description": "Found key AKIAIOSFODNN7EXAMPLE in config",
        "remediation": "Remove AKIAIOSFODNN7EXAMPLE from source",
        "severity": "high",
    }
    result = redact_dict(finding)
    assert "AKIAIOSFODNN7EXAMPLE" not in result["description"]
    assert "AKIAIOSFODNN7EXAMPLE" not in result["remediation"]
    assert "[REDACTED]" in result["description"]


def test_redact_dict_leaves_clean_finding_unchanged():
    finding = {
        "title": "Open Port 80",
        "description": "Port 80 is open and running http",
        "remediation": "Close unnecessary ports",
        "severity": "low",
    }
    result = redact_dict(finding)
    assert result["description"] == finding["description"]
    assert result["remediation"] == finding["remediation"]


def test_redact_dict_handles_nested_metadata():
    finding = {
        "title": "Secret Found",
        "description": "clean description",
        "metadata": {
            "raw_value": "password=hunter2",
            "port": 443,
        },
    }
    result = redact_dict(finding)
    assert "hunter2" not in result["metadata"]["raw_value"]
    assert result["metadata"]["port"] == 443  # non-string left untouched


def test_redact_dict_handles_none_proof():
    finding = {
        "title": "Finding",
        "description": "clean",
        "proof": None,
    }
    # Must not raise — None is not a string
    result = redact_dict(finding)
    assert result["proof"] is None


def test_redact_dict_handles_missing_keys_gracefully():
    finding = {"title": "Minimal finding", "severity": "info"}
    result = redact_dict(finding)
    assert result["title"] == "Minimal finding"


# ---------------------------------------------------------------------------
# Integration: executor INSERT paths call redact_dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_upsert_findings_redacts_description_before_insert(
    setup_test_environment,
):
    """
    _upsert_findings_and_report must call redact_dict on each finding
    before the INSERT so secrets never reach the DB.
    """
    from backend.secuscan.executor import TaskExecutor
    from backend.secuscan.database import init_db, get_db
    from backend.secuscan.config import settings

    await init_db(settings.database_path)
    db = await get_db()

    task_id = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO tasks (id, plugin_id, tool_name, target, inputs_json,
                           status, consent_granted, safe_mode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (task_id, "nmap", "nmap", "127.0.0.1",
         '{"target":"127.0.0.1"}', "completed", 1, 1),
    )

    executor = TaskExecutor()

    mock_plugin = MagicMock()
    mock_plugin.name = "nmap"
    mock_plugin.id = "nmap"
    mock_plugin.category = "Network"
    mock_plugin.output = {"parser": "builtin_nmap", "format": "text"}

    # Finding whose description contains a secret
    secret = "AKIAIOSFODNN7EXAMPLE"
    findings_data = [
        {
            "title": "Open Port",
            "category": "Network",
            "severity": "low",
            "description": f"Found credential {secret} in banner",
            "remediation": f"Remove {secret}",
            "proof": None,
            "cvss": None,
            "cve": None,
            "metadata": {},
        }
    ]

    with patch.object(executor, "_parse_results") as mock_parse, \
         patch("backend.secuscan.executor.get_plugin_manager"):
        mock_parse.return_value = {
            "findings": findings_data,
            "count": 1,
        }
        await executor._upsert_findings_and_report(
            db=db,
            task_id=task_id,
            plugin=mock_plugin,
            plugin_id="nmap",
            target="127.0.0.1",
            status="completed",
            output="",
        )

    # Check the DB row — secret must not be present
    row = await db.fetchone(
        "SELECT description, remediation FROM findings WHERE task_id = ?",
        (task_id,),
    )
    assert row is not None
    assert secret not in row["description"], (
        f"Secret found in DB description: {row['description']!r}\n"
        "redact_dict() was not called before INSERT"
    )
    assert secret not in row["remediation"]
    assert "[REDACTED]" in row["description"]