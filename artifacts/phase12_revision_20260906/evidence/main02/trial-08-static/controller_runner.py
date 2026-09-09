from pathlib import Path
from controller import main
assert main.POLL_INTERVAL == 60 and main.FEATURE_WINDOW == 300
main.read_phase = lambda: 'static'
main.ports_for_phase = lambda phase: [{"port":22,"protocol":"tcp"},{"port":23,"protocol":"tcp"}]
main.run(Path('/tmp/phase12-main-20260907-02/trial-08-static/zeek'), dry_run=False)
