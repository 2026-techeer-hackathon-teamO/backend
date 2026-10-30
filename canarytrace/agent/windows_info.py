"""Local, non-network hardware queries. Removable is not automatically USB."""
import ctypes
import os
import socket
import json
import subprocess
from functools import lru_cache
from pathlib import Path


def run_powershell(command, *, timeout=15, check=True):
    """Keep Korean account, volume and error text intact on Windows PowerShell 5.1."""
    command = '[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); ' + command
    return subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
        capture_output=True, encoding='utf-8', check=check, timeout=timeout,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )


@lru_cache(maxsize=1)
def current_user():
    if os.name != 'nt':
        return {'windows_user': 'UNKNOWN', 'windows_sid': 'UNKNOWN'}
    command = "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); @{windows_user=$i.Name;windows_sid=$i.User.Value}|ConvertTo-Json -Compress"
    p = run_powershell(command)
    return json.loads(p.stdout)


def usb_volumes():
    """Enumerate actual mounted USB-bus volumes; failure is not an empty inventory."""
    command = "$ErrorActionPreference='Stop'; $items=@(Get-Disk | Where-Object {$_.BusType -eq 'USB'} | ForEach-Object {$d=$_; Get-Partition -DiskNumber $d.Number | Where-Object {$_.DriveLetter} | ForEach-Object {@{drive=([string]$_.DriveLetter)+':';storage_type='USB';usb_device_id=[string]$d.UniqueId;volume_id=[string]$_.Guid}}}); ConvertTo-Json -InputObject $items -Compress"
    p = run_powershell(command, timeout=20)
    return json.loads(p.stdout)


def local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return 'UNKNOWN'


@lru_cache(maxsize=32)
def storage_info(drive):
    result = {'storage_type': 'UNKNOWN', 'volume_id': None, 'usb_device_id': None}
    if os.name != 'nt' or not drive:
        return result
    root = drive + '\\'
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kind = kernel.GetDriveTypeW(ctypes.c_wchar_p(root))
    result['storage_type'] = {2: 'REMOVABLE', 3: 'LOCAL', 4: 'NETWORK'}.get(kind, 'UNKNOWN')
    serial = ctypes.c_ulong()
    if kernel.GetVolumeInformationW(ctypes.c_wchar_p(root), None, 0, ctypes.byref(serial), None, None, None, 0):
        result['volume_id'] = f'{serial.value:08X}'
    if len(drive) == 2 and drive[0].isalpha() and drive[1] == ':' and kind in (2, 3):
        command = f"Get-Partition -DriveLetter {drive[0]} -ErrorAction Stop | Get-Disk | Select-Object BusType,SerialNumber,UniqueId | ConvertTo-Json -Compress"
        try:
            proc = run_powershell(command, check=False)
            if proc.returncode == 0:
                disk = json.loads(proc.stdout)
                if str(disk['BusType']).upper() in {'USB', '7'}:
                    result.update(storage_type='USB', usb_device_id=str(disk.get('UniqueId') or disk.get('SerialNumber') or '') or None)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    return result


def file_identity(path):
    s = Path(path).stat()
    return f'{s.st_dev}:{s.st_ino}'
