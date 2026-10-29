#!/usr/bin/env python3
"""Disposable two-database OAuth/MCP isolation check; stdlib only.

Start one disposable Odoo server whose dbfilter maps the first host label to a
database (e.g. ``--db-filter '^(?=<prefix>)%d$'``), mint keys and codes in each
database with ``scripts/mint_key.py``, then run this script. Requests use the
cloudflared shape (original Host + X-Forwarded-Proto) unless noted.
"""
import argparse
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import xmlrpc.client

CLIENT = 'https://client.example.test/client.json'
CALLBACK = 'https://client.example.test/cb'
PING = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping', 'params': {'_meta': {
    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientInfo': {'name': 'isolation', 'version': '1'},
    'io.modelcontextprotocol/clientCapabilities': {},
}}}).encode()


def call(base, db, path, key=None, data=None, secure=True, db_header=None, forwarded_host=False):
    host = f'{db}.example.test'
    headers = {'Host': host, 'X-Forwarded-Proto': 'https' if secure else 'http'}
    if forwarded_host:
        headers['X-Forwarded-Host'] = host
    if db_header:
        headers['X-Odoo-Database'] = db_header
    if key:
        headers['Authorization'] = 'Bearer ' + key
    if data is not None:
        headers['Content-Type'] = ('application/json' if path == '/mcp' or path.startswith('/json/2/')
                                   else 'text/xml' if path.startswith('/xmlrpc/')
                                   else 'application/x-www-form-urlencoded')
        if path == '/mcp':
            headers['MCP-Protocol-Version'] = '2026-07-28'
            headers['Mcp-Method'] = 'ping'
    req = urllib.request.Request(base + path, data=data, headers=headers,
                                 method='POST' if data is not None else 'GET')
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def token_form(code, verifier, resource):
    return urllib.parse.urlencode({
        'grant_type': 'authorization_code', 'code': code, 'client_id': CLIENT,
        'redirect_uri': CALLBACK, 'code_verifier': verifier, 'resource': resource,
    }).encode()


def main():
    parser = argparse.ArgumentParser()
    for name in ('base', 'db-a', 'db-b', 'key-a', 'key-b', 'legacy-key-a',
                 'verifier-a', 'code-a', 'code2-a'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    base = args.base.rstrip('/')
    resource_a = f'https://{args.db_a}.example.test/mcp'
    resource_b = f'https://{args.db_b}.example.test/mcp'
    checks = []

    def check(label, result):
        checks.append(bool(result))
        print(('PASS' if result else 'FAIL') + ' ' + label)

    for db, own, foreign in ((args.db_a, args.key_a, args.key_b), (args.db_b, args.key_b, args.key_a)):
        check(db + ' own MCP key', call(base, db, '/mcp', own, PING)[0] == 200)
        check(db + ' foreign MCP key rejected', call(base, db, '/mcp', foreign, PING)[0] == 401)
        status, body = call(base, db, '/.well-known/oauth-authorization-server')
        check(db + ' issuer (cloudflared shape)',
              status == 200 and json.loads(body).get('issuer') == f'https://{db}.example.test')
        status, body = call(base, db, '/.well-known/oauth-protected-resource/mcp', forwarded_host=True)
        check(db + ' resource (ProxyFix shape)',
              status == 200 and json.loads(body).get('resource') == f'https://{db}.example.test/mcp')
        check(db + ' insecure metadata 404',
              call(base, db, '/.well-known/oauth-authorization-server', secure=False)[0] == 404)
        status, _ = call(base, db, '/mcp', None, PING, secure=False)
        check(db + ' insecure /mcp still 401 (not 404)', status == 401)
    check('legacy key on A', call(base, args.db_a, '/mcp', args.legacy_key_a, PING)[0] == 200)
    check('X-Odoo-Database B under host A cannot use B key',
          call(base, args.db_a, '/mcp', args.key_b, PING, db_header=args.db_b)[0] != 200)
    check('MCP key rejected by JSON-2',
          call(base, args.db_a, '/json/2/res.users/search_count', args.key_a, b'{}')[0] in (401, 403))
    xml = xmlrpc.client.dumps((args.db_a, 'admin', args.key_a, {}), methodname='authenticate',
                              allow_none=True).encode()
    status, body = call(base, args.db_a, '/xmlrpc/2/common', data=xml)
    rejected = status in (401, 403)
    if status == 200:
        try:
            rejected = not xmlrpc.client.loads(body)[0][0]
        except xmlrpc.client.Fault:
            rejected = True
    check('MCP key rejected by XML-RPC', rejected)

    # Codes: A's code is useless at B (different database.secret) and with B's resource at A.
    check('code A at B token endpoint rejected',
          call(base, args.db_b, '/oauth/token', data=token_form(args.code_a, args.verifier_a, resource_b))[0] == 400)
    check('code A with resource B at A rejected',
          call(base, args.db_a, '/oauth/token', data=token_form(args.code_a, args.verifier_a, resource_b))[0] == 400)
    check('code A wrong verifier rejected',
          call(base, args.db_a, '/oauth/token', data=token_form(args.code_a, 'x' * 43, resource_a))[0] == 400)

    # Sequential: first exchange works, replay fails and revokes the issued key.
    status, body = call(base, args.db_a, '/oauth/token', data=token_form(args.code_a, args.verifier_a, resource_a))
    token = json.loads(body).get('access_token') if status == 200 else None
    check('code A exchange', token)
    check('issued token works on A', token and call(base, args.db_a, '/mcp', token, PING)[0] == 200)
    check('issued token rejected on B', token and call(base, args.db_b, '/mcp', token, PING)[0] == 401)
    check('replay rejected',
          call(base, args.db_a, '/oauth/token', data=token_form(args.code_a, args.verifier_a, resource_a))[0] == 400)
    check('replay revoked issued token', token and call(base, args.db_a, '/mcp', token, PING)[0] == 401)

    # Concurrent: two simultaneous exchanges of one code mint at most one live token.
    results = []
    barrier = threading.Barrier(2)

    def race():
        barrier.wait()
        results.append(call(base, args.db_a, '/oauth/token',
                            data=token_form(args.code2_a, args.verifier_a, resource_a)))

    threads = [threading.Thread(target=race) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = sorted(status for status, _ in results)
    print('  concurrent statuses:', statuses)
    winners = [json.loads(body)['access_token'] for status, body in results if status == 200]
    check('concurrent: exactly one exchange succeeds', statuses == [200, 400])
    check('concurrent: winner token revoked by loser',
          winners and call(base, args.db_a, '/mcp', winners[0], PING)[0] == 401)
    return 0 if all(checks) else 1


if __name__ == '__main__':
    sys.exit(main())
