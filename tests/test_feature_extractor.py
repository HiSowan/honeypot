from controller.log_parser import ConnRecord
from controller.feature_extractor import extract_features


def _rec(**kwargs) -> ConnRecord:
    defaults = dict(
        ts=1700000000.0, uid="Ctest", src_ip="10.0.0.1", src_port=12345,
        dst_ip="192.168.0.100", dst_port=22, proto="tcp",
        duration=None, orig_bytes=None, resp_bytes=None,
        conn_state="SF", orig_pkts=None, resp_pkts=None,
    )
    defaults.update(kwargs)
    return ConnRecord(**defaults)


W_START = 1700000000.0
W_END   = 1700000010.0


def test_conn_count():
    records = [_rec(ts=1700000000.0), _rec(ts=1700000001.0)]
    f = extract_features(records, W_START, W_END)
    assert f["10.0.0.1"].conn_count == 2


def test_unique_dst_ports():
    records = [_rec(dst_port=22), _rec(dst_port=80), _rec(dst_port=22)]
    f = extract_features(records, W_START, W_END)
    assert len(f["10.0.0.1"].unique_dst_ports) == 2


def test_syn_scan_count():
    records = [_rec(conn_state="S0"), _rec(conn_state="SF")]
    f = extract_features(records, W_START, W_END)
    assert f["10.0.0.1"].syn_scan_count == 1


def test_window_excludes_out_of_range():
    records = [_rec(ts=1700000000.0), _rec(ts=1700000020.0)]
    f = extract_features(records, W_START, W_END)
    assert f["10.0.0.1"].conn_count == 1


def test_byte_totals():
    records = [_rec(orig_bytes=100, resp_bytes=200), _rec(orig_bytes=50, resp_bytes=None)]
    f = extract_features(records, W_START, W_END)
    assert f["10.0.0.1"].total_bytes_sent == 150
    assert f["10.0.0.1"].total_bytes_recv == 200


def test_to_dict_keys():
    records = [_rec()]
    f = extract_features(records, W_START, W_END)
    d = f["10.0.0.1"].to_dict()
    expected = {"ip", "conn_count", "unique_dst_ports", "unique_dst_ips",
                "total_bytes_sent", "total_bytes_recv", "syn_scan_count", "unique_protocols"}
    assert set(d.keys()) == expected
