from pathlib import Path
import pytest
from controller.log_parser import parse_conn_log

SAMPLE = """\
#separator \\x09
#set_separator ,
#empty_field (empty)
#unset_field -
#path conn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\tcount\tcount
1700000000.0\tCabc123\t10.0.0.1\t54321\t192.168.0.100\t22\ttcp\t0.5\t200\t800\tSF\t5\t6
1700000001.0\tCdef456\t10.0.0.2\t12345\t192.168.0.100\t80\ttcp\t-\t-\t-\tS0\t1\t0
"""


def test_record_count(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(SAMPLE)
    records = list(parse_conn_log(p))
    assert len(records) == 2


def test_first_record_fields(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(SAMPLE)
    r = list(parse_conn_log(p))[0]
    assert r.src_ip == "10.0.0.1"
    assert r.dst_port == 22
    assert r.proto == "tcp"
    assert r.duration == 0.5
    assert r.orig_bytes == 200
    assert r.conn_state == "SF"


def test_unset_fields_are_none(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(SAMPLE)
    r = list(parse_conn_log(p))[1]
    assert r.duration is None
    assert r.orig_bytes is None
    assert r.conn_state == "S0"


@pytest.mark.parametrize("malformed_index", range(7))
def test_malformed_rows_do_not_hide_later_valid_records(tmp_path, malformed_index):
    header, first, second = SAMPLE.rstrip('\n').rsplit('\n', 2)
    malformed = [
        '',
        first.replace('1700000000.0', 'invalid', 1),
        first.replace('1700000000.0', '-', 1),
        first.replace('1700000000.0', 'nan', 1),
        first.replace('1700000000.0', 'inf', 1),
        '\t'.join(first.split('\t')[:7]),
        first + '\textra',
    ]
    p = tmp_path / 'conn.log'
    p.write_text('\n'.join([header, first, malformed[malformed_index], second]) + '\n')
    records = list(parse_conn_log(p))
    assert [r.uid for r in records] == ['Cabc123', 'Cdef456']
