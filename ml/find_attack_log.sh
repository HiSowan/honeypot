#!/bin/bash
# Finds archived Zeek conn logs that contain Kali attacker traffic (10.10.0.2)
echo "Searching for 10.10.0.2 in archived logs..."
find /opt/zeek/logs -name "conn.*.log.gz" | while read f; do
    n=$(zcat "$f" | grep -c "10\.10\.0\.2" 2>/dev/null)
    [ "$n" -gt 0 ] && echo "$n connections: $f"
done
echo "Done."
