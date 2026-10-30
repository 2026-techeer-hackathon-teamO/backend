"""Import approved gateway JSONL audit records; does not send any email."""
import argparse
import json
from agent.windows_agent import Agent


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', required=True, help='Enrolled SMTP_GATEWAY credentials with TLS CA')
    p.add_argument('--jsonl', required=True, help='Actual gateway records: file_id, sha256, external_id, occurred_at, source, destination, evidence_reference')
    args = p.parse_args()
    agent = Agent(args.config)
    try:
        with open(args.jsonl, encoding='utf-8-sig') as records:
            for line in records:
                row = json.loads(line)
                body = {k: row[k] for k in ('file_id', 'sha256', 'external_id', 'occurred_at', 'source', 'destination', 'evidence_reference')}
                body.update(channel='EMAIL', evidence_type='SMTP_AUDIT_LOG')
                body.update({k: row[k] for k in ['distribution_id', 'issuance_id', 'message_id', 'stage', 'recipient_device_id'] if k in row})
                agent.enqueue('/api/integrations/movements', body, 'email:' + body['external_id'])
        agent.db.commit()
        agent.flush()
        if agent.db.execute('SELECT COUNT(*) FROM pending').fetchone()[0] or agent.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='rejected'").fetchone()[0] and agent.db.execute('SELECT COUNT(*) FROM rejected').fetchone()[0]:
            raise SystemExit('Some records remain pending or rejected; no complete import claimed')
        print('Gateway records processed. See spool rejected table for permanently rejected records.')
    finally:
        agent.close()


if __name__ == '__main__':
    main()
