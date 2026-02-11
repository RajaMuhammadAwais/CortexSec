import json

from cortexsec.core.audit import AuditConfig, AuditLogger


def test_forensic_logging_writes_jsonl(tmp_path):
    logger = AuditLogger(AuditConfig(log_level="forensic", log_dir=str(tmp_path)), run_id="run-1")
    logger.log("decision", {"decision": "run_nmap"})
    logger.log("tool_command", {"command": "nmap -sV localhost"})
    logger.prompt_hash("test prompt")

    lines = logger.log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    payload = [json.loads(line) for line in lines]
    assert payload[0]["event_type"] == "decision"
    assert payload[1]["event_type"] == "tool_command"
    assert payload[2]["event_type"] == "prompt_hash"


def test_anonymize_mode_hashes_sensitive_fields(tmp_path):
    logger = AuditLogger(AuditConfig(log_level="forensic", log_dir=str(tmp_path), anonymize=True), run_id="run-2")
    logger.log("decision", {"decision": "allow", "target": "example.com"})

    record = next(AuditLogger.replay(str(logger.log_path)))
    assert record["payload"]["target"] != "example.com"
    assert len(record["payload"]["target"]) == 64
