#!/usr/bin/env python3
"""Read Suricata EVE JSON alerts and print concise, non-sensitive summary."""
import json
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print('Usage: python3 scripts/read_alerts.py /var/log/suricata/eve.json')
        return 2
    path=Path(sys.argv[1]); counts={}; total=0
    with path.open(encoding='utf-8') as source:
        for line in source:
            try: evt=json.loads(line)
            except json.JSONDecodeError: continue
            if evt.get('event_type') != 'alert': continue
            alert=evt.get('alert',{})
            msg=alert.get('signature','UNKNOWN');counts[msg]=counts.get(msg,0)+1;total+=1
            print(f"{evt.get('timestamp','')} {evt.get('src_ip','?')} -> {evt.get('dest_ip','?')} {msg}")
    print('Total alerts:',total)
    for msg,count in sorted(counts.items()): print(f'{count}x {msg}')
    return 0
if __name__=='__main__': raise SystemExit(main())
