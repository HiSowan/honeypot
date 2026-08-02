"""Firewall tests — always use dry_run=True, never touch real iptables."""
from unittest.mock import patch, call
from controller.firewall import Firewall


def test_dry_run_open_port_does_not_call_subprocess():
    fw = Firewall(dry_run=True)
    with patch("subprocess.run") as mock_run:
        fw.open_port(22)
    mock_run.assert_not_called()


def test_dry_run_block_ip_does_not_call_subprocess():
    fw = Firewall(dry_run=True)
    with patch("subprocess.run") as mock_run:
        fw.block_ip("10.0.0.1")
    mock_run.assert_not_called()


def test_blocked_ips_tracked_in_dry_run():
    fw = Firewall(dry_run=True)
    fw.block_ip("10.0.0.1")
    fw.block_ip("10.0.0.2")
    assert fw.blocked_ips() == {"10.0.0.1", "10.0.0.2"}


def test_unblock_removes_from_tracked_set():
    fw = Firewall(dry_run=True)
    fw.block_ip("10.0.0.1")
    fw.unblock_ip("10.0.0.1")
    assert "10.0.0.1" not in fw.blocked_ips()


def test_double_block_is_idempotent():
    fw = Firewall(dry_run=True)
    fw.block_ip("10.0.0.1")
    fw.block_ip("10.0.0.1")
    assert len(fw.blocked_ips()) == 1


def test_unblock_unknown_ip_is_safe():
    fw = Firewall(dry_run=True)
    fw.unblock_ip("10.0.0.99")  # should not raise


def test_flush_clears_blocked_set():
    fw = Firewall(dry_run=True)
    fw.block_ip("10.0.0.1")
    fw.block_ip("10.0.0.2")
    fw.flush_chain()
    assert len(fw.blocked_ips()) == 0
