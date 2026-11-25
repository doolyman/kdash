"""Wait for stable artifact metadata before creating a Pages deployment.

Only read requests are retried. A Pages deployment is never retried here.
The short settling window also allows the Actions results service used by
deploy-pages to catch up with the REST artifact listing.
"""
import json
import os
import time
import urllib.error
import urllib.request


def fetch_metadata(url, token, timeout):
    request = urllib.request.Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + token,
        'X-GitHub-Api-Version': '2022-11-28',
        'Cache-Control': 'no-cache',
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def wait_for_artifact(name, artifact_id, fetch, *, timeout=90, interval=5,
                      settle=20, clock=time.monotonic, sleep=time.sleep):
    if not name or artifact_id <= 0 or min(timeout, interval) <= 0 or settle < 0:
        raise ValueError('Invalid artifact visibility check settings.')
    deadline = clock() + timeout
    visible_since = None
    while clock() < deadline:
        payload = None
        try:
            payload = fetch(min(15, deadline - clock()))
        except urllib.error.HTTPError as error:
            if error.code not in (404, 408, 429) and error.code < 500:
                raise RuntimeError(f'Artifact metadata request failed (HTTP {error.code}).') from None
            print(f'Artifact metadata temporarily unavailable (HTTP {error.code}); waiting.', flush=True)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            print('Artifact metadata temporarily unavailable; waiting.', flush=True)
        if payload is not None:
            if not isinstance(payload, dict) or not isinstance(payload.get('artifacts'), list):
                raise RuntimeError('Invalid artifact metadata response; deployment was not started.')
            if payload.get('total_count', len(payload['artifacts'])) > 100:
                raise RuntimeError('Too many artifacts to verify safely; deployment was not started.')
            matches = [item for item in payload['artifacts'] if item.get('name') == name]
            if len(matches) > 1:
                raise RuntimeError('Duplicate artifact names; deployment was not started.')
            if matches:
                artifact = matches[0]
                if artifact.get('id') != artifact_id or artifact.get('expired') is not False:
                    raise RuntimeError('Artifact identity or expiry mismatch; deployment was not started.')
                if artifact.get('size_in_bytes', 0) > 0:
                    if visible_since is None:
                        visible_since = clock()
                    if clock() - visible_since >= settle:
                        print(f'Artifact {name} is visible and stable; ready for Pages.', flush=True)
                        return artifact
                else:
                    visible_since = None
            else:
                visible_since = None
        else:
            visible_since = None
        remaining = deadline - clock()
        if remaining <= 0:
            break
        print(f'Waiting for artifact {name} to become visible and stable.', flush=True)
        sleep(min(interval, remaining))
    raise RuntimeError('Artifact visibility check timed out; deployment was not started.')


def main():
    token = os.environ['GITHUB_TOKEN']
    repository = os.environ['GITHUB_REPOSITORY']
    run_id = int(os.environ['GITHUB_RUN_ID'])
    name = os.environ['PAGES_ARTIFACT_NAME']
    artifact_id = int(os.environ['PAGES_ARTIFACT_ID'])
    api = os.environ.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')
    url = f'{api}/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100'
    wait_for_artifact(name, artifact_id, lambda timeout: fetch_metadata(url, token, timeout))


if __name__ == '__main__':
    try:
        main()
    except (KeyError, ValueError, RuntimeError) as error:
        # Do not print response bodies, request headers, or credentials.
        print(f'Artifact preflight failed: {error}', flush=True)
        raise SystemExit(1)
