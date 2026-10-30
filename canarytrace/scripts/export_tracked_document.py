"""Export the already issued DOCX without changing its token or original source."""
import hashlib
import io
import json
import zipfile
from pathlib import Path
from docx import Document
from docx.oxml.ns import qn

ROOT = Path(__file__).resolve().parents[1]
latest = json.loads((ROOT/'artifacts/lan/latest.json').read_text('utf-8'))
with zipfile.ZipFile(latest['zip_path']) as archive:
    manifest = json.loads(archive.read('manifest.json'))
    item = next(f for f in manifest['files'] if f['mode'] == 'DOCX_REMOTE_IMAGE')
    raw = archive.read(item['archive_path'])
assert hashlib.sha256(raw).hexdigest() == item['file_hash']
document = Document(io.BytesIO(raw))
references = [document.part.rels[b.get(qn('r:link'))] for b in document.element.xpath('.//a:blip') if b.get(qn('r:link'))]
assert any(r.is_external and r.target_ref.startswith(latest['server']+'/b/') for r in references)
out = Path(latest['output'])/'ccc-canary-tracked.docx'
if out.exists():
    assert out.read_bytes() == raw, 'Existing output differs; refusing overwrite'
else:
    with out.open('xb') as target: target.write(raw)
result = {'document': str(out), 'distribution_id': item['distribution_id'], 'issuance_id': item['issuance_id'], 'token_id': item['token_id'], 'sha256': item['file_hash'], 'remote_image_reference_verified': True, 'server': latest['server'], 'automatic_word_callback': 'NOT_OBSERVED_IN_PRIOR_LIVE_TEST', 'limitation': 'Only permitted HTTP resource requests produce beacon observations. Windows user/PC name are not available from this document beacon.'}
(out.parent/'tracked-document-verification.json').write_text(json.dumps(result, indent=2), 'utf-8')
print(json.dumps(result, indent=2))
