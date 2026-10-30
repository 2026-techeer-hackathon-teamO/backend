"""Bounded ZIP handling with Windows-safe paths; never use extractall on input."""
import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path

MAX_FILES = 200
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024


def safe_member(name):
    if not name or len(name) > 240 or '\\' in name or name.startswith('/'):
        raise ValueError('Unsafe archive path')
    parts = name.rstrip('/').split('/')
    for part in parts:
        if part in {'', '.', '..'} or part.endswith((' ', '.')) or re.search(r'[\x00-\x1f\x7f<>:"|?*]', part):
            raise ValueError('Unsafe archive path')
        if re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', part):
            raise ValueError('Reserved Windows filename')
    return '/'.join(parts)


def zip_entries(raw):
    if len(raw) > MAX_TOTAL:
        raise ValueError('Archive too large')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_TOTAL:
            raise ValueError('Archive expansion limit exceeded')
        seen, result = set(), {}
        for entry in infos:
            name = safe_member(entry.filename)
            key = name.casefold()
            if key in seen:
                raise ValueError('Duplicate or conflicting archive path')
            seen.add(key)
            mode = entry.external_attr >> 16
            if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError('Archive links and special files are forbidden')
            if entry.flag_bits & 1:
                raise ValueError('Encrypted archive unsupported')
            if entry.file_size > MAX_FILE or entry.file_size > max(1, entry.compress_size) * 500:
                raise ValueError('Archive member expansion limit exceeded')
            if not entry.is_dir():
                with archive.open(entry) as source:
                    data = source.read(MAX_FILE + 1)
                if len(data) != entry.file_size or len(data) > MAX_FILE:
                    raise ValueError('Archive size mismatch')
                result[name] = data
        keys = {x.casefold() for x in result}
        if any('/'.join(k.split('/')[:i]) in keys for k in keys for i in range(1, len(k.split('/')))):
            raise ValueError('Conflicting archive path')
        return result


def no_link(path):
    info = path.lstat()
    # OneDrive cloud placeholders are allowed; name-surrogate reparse points are not.
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_reparse_tag', 0) & 0x20000000:
        raise ValueError('Symlink or junction forbidden: ' + str(path))
    return info


def source_files(source):
    source = Path(source).absolute()
    no_link(source)
    paths, directories = [], []
    def walk(folder, depth=0):
        directories.append(folder)
        if depth > 32 or len(directories) > 2000:
            raise ValueError('Source directory traversal limit exceeded')
        for child in sorted(folder.iterdir()):
            info = no_link(child)
            if stat.S_ISDIR(info.st_mode):
                walk(child, depth + 1)
            elif stat.S_ISREG(info.st_mode):
                paths.append(child)
                if len(paths) > MAX_FILES:
                    raise ValueError('Source file count limit exceeded')
            else:
                raise ValueError('Special file forbidden')
    if source.is_dir():
        walk(source)
    else:
        paths = [source]
    total, result = 0, {}
    for path in paths:
        before = no_link(path)
        if before.st_size > MAX_TOTAL:
            raise ValueError('Source file too large')
        with path.open('rb') as stream:
            raw = stream.read(MAX_TOTAL + 1)
        after = path.stat()
        if len(raw) > MAX_TOTAL or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('Source changed or exceeds limit')
        total += len(raw)
        if total > MAX_TOTAL:
            raise ValueError('Source total size limit exceeded')
        name = path.relative_to(source).as_posix() if source.is_dir() else path.name
        safe_member(name)
        result[name] = raw
    return result


def extract_verified(raw, destination):
    entries = zip_entries(raw)
    destination = Path(destination)
    # A fresh directory avoids overwrites and pre-existing symlink components.
    parent = destination.parent.resolve(strict=True)
    for ancestor in [destination.parent, *destination.parent.parents]:
        no_link(ancestor)
    destination = parent / destination.name
    destination.mkdir(exist_ok=False)
    for name, data in entries.items():
        path = destination.joinpath(*name.split('/'))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(data).digest():
            raise ValueError('Extracted hash mismatch')
    return entries
