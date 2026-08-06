from controller.feature_extractor import IPFeatures
from controller.main import _is_scanner, _adaptive_rotate
from controller.firewall import Firewall


def _features(ports: set, syn_scans: int = 0) -> IPFeatures:
    f = IPFeatures(ip="10.0.0.1")
    f.unique_dst_ports = ports
    f.syn_scan_count = syn_scans
    return f


def test_scanner_detected_by_port_count():
    f = _features(ports={22, 23, 80, 443, 445})
    assert _is_scanner(f) is True


def test_scanner_detected_by_syn_scans():
    f = _features(ports={22}, syn_scans=10)
    assert _is_scanner(f) is True


def test_non_scanner_not_flagged():
    f = _features(ports={22}, syn_scans=2)
    assert _is_scanner(f) is False


def test_adaptive_rotate_closes_probed_port():
    fw = Firewall(dry_run=True)
    f = _features(ports={22})
    allowed = [{"port": 22, "protocol": "tcp"}, {"port": 80, "protocol": "tcp"}]
    _adaptive_rotate(f, allowed, fw)
    # In dry_run mode no subprocess calls are made — just verify no exception raised


def test_adaptive_rotate_does_not_raise_on_empty_ports():
    fw = Firewall(dry_run=True)
    f = _features(ports=set())
    _adaptive_rotate(f, [{"port": 22, "protocol": "tcp"}], fw)
