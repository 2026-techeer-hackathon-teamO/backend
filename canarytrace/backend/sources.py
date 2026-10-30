"""Admin-selected Desktop ccc ingestion; never accepts arbitrary server paths."""
import hashlib
import io
import json
import subprocess
from pathlib import Path
from typing import Literal
from fastapi import Depends, HTTPException, UploadFile
from pydantic import BaseModel
from .db import Record, add, audit, now, public, rows
from .archives import zip_entries


class SourceImport(BaseModel):
    source_id: str
    fingerprint: str
    approved_test_documents: Literal[True]
    synthetic: bool = False
    classification: Literal['CONFIDENTIAL', 'RESTRICTED'] = 'CONFIDENTIAL'


def fingerprint(report):
    return hashlib.sha256(json.dumps(report['fingerprint'], sort_keys=True).encode()).hexdigest()


def install_sources(app, *, session, admin, register_file):
    from scripts.ccc_distribution import desktop_context, inspect_source, synthetic_documents, file_info
    def scan():
        try:
            context = desktop_context()
            sources = []
            for path in context['candidates']:
                identifier = hashlib.sha256(path.casefold().encode()).hexdigest()
                try:
                    report, _ = inspect_source(Path(path))
                    sources.append({'source_id': identifier, **report, 'fingerprint_id': fingerprint(report), 'status': 'EMPTY' if report['file_count'] == 0 else 'READY_FOR_REVIEW'})
                except (OSError, ValueError) as exc:
                    sources.append({'source_id': identifier, 'source_path': path, 'status': 'UNREADABLE_OR_UNSAFE', 'error_type': type(exc).__name__})
            return {'context': context, 'sources': sources}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            raise HTTPException(409, 'Desktop discovery unavailable: ' + type(exc).__name__)

    @app.get('/api/sources/ccc')
    def discover(account=Depends(admin), db=Depends(session)):
        result = scan()
        result['registrations'] = [public(r) for r in rows(db, 'source_registration')]
        return result

    @app.post('/api/sources/ccc/import')
    async def ingest(body: SourceImport, account=Depends(admin), db=Depends(session)):
        result = scan()
        selected = next((s for s in result['sources'] if s['source_id'] == body.source_id), None)
        if not selected or selected['status'] == 'UNREADABLE_OR_UNSAFE':
            raise HTTPException(404, 'Discovered readable ccc source required')
        if selected['fingerprint_id'] != body.fingerprint:
            raise HTTPException(409, 'Source changed; inspect again before importing')
        try:
            before, content = inspect_source(Path(selected['source_path']))
        except (OSError, ValueError) as exc:
            raise HTTPException(422, 'Unreadable or unsafe source') from exc
        if fingerprint(before) != body.fingerprint:
            raise HTTPException(409, 'Source changed before registration; inspect again')
        docs = synthetic_documents() if body.synthetic else {}
        if not body.synthetic:
            for name, raw in content.items():
                info = file_info(name, raw)
                if info['actual_format'] == 'ZIP':
                    try:
                        docs.update({name + '/' + n: b for n, b in zip_entries(raw).items()})
                    except ValueError as exc:
                        raise HTTPException(422, 'Unsafe or encrypted archive') from exc
                else: docs[name] = raw
            if not docs: raise HTTPException(409, 'ccc is empty; explicitly select synthetic test documents')
            for name, raw in docs.items():
                info = file_info(name, raw)
                if not info['supported'] or info['existing_canary'] != 'NOT_DETECTED_HEURISTIC':
                    raise HTTPException(422, 'Unsupported/encrypted/previously tracked source; use approved synthetic data')
        identifiers = []
        for name, raw in docs.items():
            sha = hashlib.sha256(raw).hexdigest()
            old = next((r for r in rows(db, 'file') if r.data['sha256'] == sha), None)
            if old:
                if not old.data['active'] or old.data['classification'] not in {'CONFIDENTIAL', 'RESTRICTED'}:
                    raise HTTPException(409, 'Existing matching source is inactive or excluded by policy')
                identifiers.append(old.id)
            else:
                registered = await register_file(UploadFile(filename=Path(name).name, file=io.BytesIO(raw)), body.classification, account, db)
                identifiers.append(registered['id'])
        after, _ = inspect_source(Path(selected['source_path']))
        if before['fingerprint'] != after['fingerprint']:
            raise HTTPException(409, 'Source changed during registration; no distribution created')
        row = add(db, 'source_registration', {'source_id': body.source_id, 'source_path': selected['source_path'], 'source_fingerprint': body.fingerprint, 'source_preserved': True, 'source_kind': 'SYNTHETIC_TEST_DATA' if body.synthetic else 'APPROVED_SOURCE', 'file_ids': list(dict.fromkeys(identifiers)), 'registered_at': now(), 'approved_by': account.id})
        audit(db, account.id, 'CCC_REGISTERED', row.id, source_kind=row.data['source_kind'])
        db.commit()
        return public(row)
