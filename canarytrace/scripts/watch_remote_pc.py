"""Watch for other enrolled devices and new authenticated file reads; never synthesize events."""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.ccc_distribution import api_client


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seconds',type=int,default=300)
    args=p.parse_args()
    if not 1 <= args.seconds <= 3600: p.error('seconds must be between 1 and 3600')
    config=ROOT/'.runtime/agent.json'
    local=json.loads(config.read_text('utf-8-sig'))['device_id'] if config.exists() else None
    started=datetime.now(timezone.utc)
    result={'started_at':started.isoformat(),'local_device_id':local,'other_active_devices':[],'new_file_events':[],'status':'WAITING_FOR_OTHER_DEVICE','limitation':'Different enrolled device identity is not hardware attestation; verify the reported PC with the approved operator.'}
    target=ROOT/'artifacts/remote-pc-readiness.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    seen=set();end=time.monotonic()+args.seconds
    with api_client() as c:
        while True:
            response=c.get('/api/devices');response.raise_for_status()
            others=[d for d in response.json() if d['id']!=local and d['active'] and d['kind']=='WINDOWS_AGENT']
            ids={d['id'] for d in others}
            result['other_active_devices']=[{k:d.get(k) for k in ['id','name','last_seen']} for d in others]
            if others:
                response=c.get('/api/events');response.raise_for_status()
                for event in response.json():
                    if event.get('device_id') not in ids or event['source_type']!='WINDOWS_SECURITY_4663':continue
                    if datetime.fromisoformat(event['received_at'])<started or event['event_id'] in seen:continue
                    seen.add(event['event_id'])
                    item={k:event.get(k) for k in ['event_id','pc_name','windows_user','device_id','process','object_path','received_at','distribution_id','issuance_id','observed_public_ip']}
                    result['new_file_events'].append(item)
                    print(json.dumps({'received_file_event':item},ensure_ascii=False),flush=True)
            result['status']='OTHER_DEVICE_FILE_EVENT_RECEIVED' if seen else ('OTHER_DEVICE_ENROLLED_WAITING_FOR_READ' if others else 'WAITING_FOR_OTHER_DEVICE')
            result['checked_at']=datetime.now(timezone.utc).isoformat()
            target.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
            if seen or time.monotonic()>=end:break
            time.sleep(min(5,max(0,end-time.monotonic())))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
