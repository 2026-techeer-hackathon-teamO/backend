"""Evidence-preserving correlation. No hash-only attribution of a transfer route."""
from datetime import datetime


def correlate(event, movements, observations, hours=48):
    at = datetime.fromisoformat(event['occurred_at'])
    candidates = []
    relevant = []
    for movement in movements:
        m = movement
        delta = (at - datetime.fromisoformat(m['occurred_at'])).total_seconds()
        if not 0 <= delta <= hours * 3600: continue
        same_issuance = bool(event.get('issuance_id') and m.get('issuance_id') == event['issuance_id'])
        same_distribution = bool(event.get('distribution_id') and m.get('distribution_id') == event['distribution_id'])
        same_file = bool(event.get('file_id') and m.get('file_id') == event['file_id'])
        same_hash = bool(event.get('sha256') and event['sha256'] == m.get('sha256'))
        if not (same_issuance or same_distribution or (same_file and (same_hash or not event.get('sha256')))): continue
        if event.get('issuance_id') and m.get('issuance_id') and not same_issuance: continue
        device_match = bool(event.get('device_id') and m.get('recipient_device_id') == event['device_id'])
        usb_match = bool(event.get('usb_device_id') and m.get('usb_device_id') == event['usb_device_id'])
        connections = [o for o in observations if m.get('usb_device_id') and o.get('usb_device_id') == m['usb_device_id'] and o.get('device_id') == event.get('device_id') and o['event_type'] in {'USB_CONNECTED', 'USB_PRESENT'} and datetime.fromisoformat(m['occurred_at']) <= datetime.fromisoformat(o['occurred_at']) <= at]
        if connections: usb_match = True
        level = 'CORRELATED' if (same_issuance or same_distribution) and (device_match or usb_match) else 'INFERRED'
        relevant.append(m)
        candidates.append({'movement_id': m['id'], 'channel': m['channel'], 'evidence_level': level, 'same_issuance': same_issuance, 'same_distribution': same_distribution, 'same_hash': same_hash, 'recipient_device_match': device_match, 'usb_identity_match': usb_match, 'message_id': m.get('message_id'), 'connection_observations': [o['id'] for o in connections], 'route_confirmed': False})
    extracts = [o for o in observations if o['event_type'] == 'ZIP_EXTRACTED' and event.get('distribution_id') and o.get('distribution_id') == event['distribution_id'] and o.get('device_id') == event.get('device_id') and 0 <= (at - datetime.fromisoformat(o['occurred_at'])).total_seconds() <= hours * 3600]
    stages = {m.get('stage') or ('FILE_COPIED_TO_USB' if m['channel'] == 'USB' else 'EMAIL_ATTACHMENT_SENT') for m in relevant}
    # A completed SMTP delivery is only tied to its own logged message/recipient.
    graph = [{'step': name, 'evidence': 'CONFIRMED' if name in stages else 'UNKNOWN'} for name in ['FILE_COPIED_TO_USB', 'EMAIL_ATTACHMENT_SENT', 'EMAIL_DELIVERED', 'FILE_DOWNLOADED']]
    graph += [{'step': 'USB_CONNECTED_TO_PC', 'evidence': 'CONFIRMED' if any(c['connection_observations'] for c in candidates) else 'UNKNOWN'}, {'step': 'FILE_EXTRACTED', 'evidence': 'CONFIRMED' if extracts else 'UNKNOWN', 'observation_ids': [o['id'] for o in extracts]}, {'step': 'FILE_OPENED', 'evidence': 'CONFIRMED' if event['source_type'] == 'WINDOWS_SECURITY_4663' else 'UNKNOWN', 'note': 'File read access only; human reading remains UNKNOWN'}]
    return {'candidates': candidates, 'observed_movements': relevant, 'evidence_graph': graph, 'route': 'UNKNOWN', 'relation_evidence': 'CORRELATED' if any(c['evidence_level'] == 'CORRELATED' for c in candidates) else ('INFERRED' if candidates else 'UNKNOWN'), 'correlation': 'IDENTIFIER_AND_TIME_CANDIDATE' if candidates else 'NONE', 'relation_confidence': 'INFERRED_RELATION' if candidates else 'NONE', 'note': 'Individual observations are confirmed separately. Matching identifiers and time do not prove a unique transfer path or recipient identity.'}
