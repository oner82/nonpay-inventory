"""운영 문서에 쓰지 않고 인증 전환용 접근 규칙만 배포한다."""
import json
import os
from pathlib import Path
import subprocess
from urllib import error, request

PROJECT = 'nonpay-inventory'
BASE = 'https://firebaserules.googleapis.com/v1/projects/' + PROJECT
BUCKET = 'nonpay-inventory.firebasestorage.app'
token = subprocess.check_output(['gcloud', 'auth', 'print-access-token'], text=True).strip()


def api(method, url, body=None):
    req = request.Request(url, method=method, headers={'Authorization': 'Bearer ' + token,
                           'Content-Type': 'application/json'},
                          data=json.dumps(body).encode() if body is not None else None)
    try:
        with request.urlopen(req, timeout=30) as res:
            return json.load(res)
    except error.HTTPError as exc:
        detail = json.load(exc).get('error', {})
        raise RuntimeError(f"{method} {url}: {exc.code} {detail.get('message', '')}") from None


def lockdown(release, filename):
    url = BASE + '/releases/' + release
    previous = api('GET', url)
    # Google의 불변 규칙 버전 식별자를 보관한다. 문서와 사진은 조회하지 않는다.
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write(f"기존 {release} 규칙 버전 `{previous['rulesetName']}`\n\n")
    content = Path(__file__).with_name(filename).read_text()
    source = {'files': [{'name': filename, 'content': content}]}
    result = api('POST', BASE + ':test', {'source': source})
    if any(i.get('severity') == 'ERROR' for i in result.get('issues', [])):
        raise RuntimeError(f'{release}: 규칙 컴파일 실패')
    ruleset = api('POST', BASE + '/rulesets', {'source': source})
    api('PATCH', url, {'release': {'name': previous['name'], 'rulesetName': ruleset['name']},
                       'updateMask': 'rulesetName'})
    if api('GET', url)['rulesetName'] != ruleset['name']:
        raise RuntimeError(f'{release}: 적용된 규칙 버전이 다릅니다.')
    print(f'{release}: 차단 규칙 적용 및 버전 확인')


if __name__ == '__main__':
    failures = []
    for release, filename in [('cloud.firestore', 'lockdown.firestore.rules'),
                              ('firebase.storage/' + BUCKET, 'lockdown.storage.rules')]:
        try:
            lockdown(release, filename)
        except RuntimeError as exc:
            failures.append(str(exc))
    if failures:
        raise SystemExit('\n'.join(failures))
