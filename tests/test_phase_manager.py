import pytest
from controller.phase_manager import read_phase, ports_for_phase


def test_read_valid_phase(tmp_path):
    p = tmp_path / "phase.conf"
    p.write_text("phase=static\n")
    assert read_phase(p) == "static"


def test_read_phase_ignores_comments(tmp_path):
    p = tmp_path / "phase.conf"
    p.write_text("# comment\nphase=adaptive\n")
    assert read_phase(p) == "adaptive"


def test_read_invalid_phase_raises(tmp_path):
    p = tmp_path / "phase.conf"
    p.write_text("phase=unknown\n")
    with pytest.raises(ValueError, match="Unknown phase"):
        read_phase(p)


def test_read_missing_key_raises(tmp_path):
    p = tmp_path / "phase.conf"
    p.write_text("# no phase key\n")
    with pytest.raises(ValueError, match="No 'phase' key"):
        read_phase(p)


def test_ports_for_static_phase(tmp_path):
    yaml_content = """
ports:
  - port: 22
    protocol: tcp
    service: cowrie-ssh
    phases: [static, adaptive]
  - port: 9999
    protocol: tcp
    service: future-only
    phases: [adaptive_ml]
"""
    p = tmp_path / "ports.yaml"
    p.write_text(yaml_content)
    result = ports_for_phase("static", p)
    assert len(result) == 1
    assert result[0]["port"] == 22


def test_ports_for_adaptive_ml_gets_all(tmp_path):
    yaml_content = """
ports:
  - port: 22
    protocol: tcp
    service: cowrie-ssh
    phases: [static, adaptive, adaptive_ml]
  - port: 9999
    protocol: tcp
    service: future-only
    phases: [adaptive_ml]
"""
    p = tmp_path / "ports.yaml"
    p.write_text(yaml_content)
    result = ports_for_phase("adaptive_ml", p)
    assert len(result) == 2
