"""Korean text is verified through actual local PowerShell pipes, not a device simulation."""
import json
import os

import pytest

from agent.windows_info import run_powershell
from agent.windows_agent import parse_4663
from conftest import xml_event


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell 5.1 is required')
def test_powershell_preserves_korean_stdout_and_stderr():
    result = run_powershell(
        "@{windows_user='테스트회사\\홍길동';path='C:\\승인문서\\기밀.txt'} | ConvertTo-Json -Compress; "
        "[Console]::Error.WriteLine('한글 오류 메시지')"
    )
    value = json.loads(result.stdout)
    assert value['windows_user'] == '테스트회사\\홍길동'
    assert value['path'] == 'C:\\승인문서\\기밀.txt'
    assert '한글 오류 메시지' in result.stderr
    assert '\ufffd' not in result.stdout + result.stderr


def test_security_xml_preserves_korean_identity_and_path():
    raw = xml_event('C:\\승인문서\\기밀 자료.txt', process='C:\\프로그램\\문서뷰어.exe')
    raw = raw.replace('TEST-MANAGED-PC', '테스트컴퓨터').replace('>employee<', '>홍길동<')
    event = parse_4663(raw)
    assert event['pc_name'] == '테스트컴퓨터'
    assert event['windows_user'] == 'TEST\\홍길동'
    assert event['object_path'] == 'C:\\승인문서\\기밀 자료.txt'
    assert event['process'] == 'C:\\프로그램\\문서뷰어.exe'
