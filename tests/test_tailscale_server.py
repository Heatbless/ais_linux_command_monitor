import argparse
import asyncio
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from ais.server import cli
from ais.server.app import create_app


@pytest.mark.parametrize('address', ['0.0.0.0', '43.128.81.70', '127.0.0.1', '::', 'example.com'])
def test_tailscale_address_rejects_non_tailnet(address):
    with pytest.raises(ValueError):
        cli.tailscale_address(address)


def test_tailscale_auto_detection(monkeypatch):
    run = Mock(return_value=SimpleNamespace(stdout='100.80.216.26\n'))
    monkeypatch.setattr(cli.subprocess, 'run', run)
    assert cli.tailscale_address('auto') == '100.80.216.26'
    assert run.call_args.args[0] == ['tailscale', 'ip', '-4']
    assert run.call_args.kwargs['check'] is True


@pytest.mark.parametrize('failure', [subprocess.TimeoutExpired('tailscale', 5),
                                     subprocess.CalledProcessError(1, 'tailscale')])
def test_tailscale_detection_failure_propagates(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(cli.subprocess, 'run', fail)
    with pytest.raises(subprocess.SubprocessError):
        cli.tailscale_address('auto')


@pytest.mark.parametrize('tailnet,expected', [(None, ['127.0.0.1']),
                                            ('100.80.216.26', ['127.0.0.1', '100.80.216.26'])])
def test_listener_scope_and_cleanup(monkeypatch, tailnet, expected):
    import uvicorn
    import ais.server.app as app_module
    monkeypatch.delenv('AIS_OPERATOR_ORIGIN', raising=False)
    monkeypatch.delenv('AIS_ALLOWED_HOSTS', raising=False)
    sockets = []
    def make_socket(*args):
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        sockets.append(sock)
        return sock
    monkeypatch.setattr(cli.socket, 'socket', make_socket)
    factory = Mock(return_value=object())
    monkeypatch.setattr(app_module, 'create_app', factory)
    server = Mock()
    monkeypatch.setattr(uvicorn, 'Server', Mock(return_value=server))
    cli.serve(argparse.Namespace(database='unused.sqlite', tailscale=tailnet))
    assert [sock.bind.call_args.args[0] for sock in sockets] == [(ip, 8000) for ip in expected]
    assert factory.call_args.kwargs['allowed_hosts'] == ['127.0.0.1', 'localhost'] + expected[1:]
    assert factory.call_args.kwargs['additional_origins'] == [f'http://{ip}:8000' for ip in expected[1:]]
    server.run.assert_called_once_with(sockets=sockets)
    assert all(sock.__exit__.called for sock in sockets)


def test_https_configuration_is_not_weakened(monkeypatch):
    monkeypatch.setenv('AIS_OPERATOR_ORIGIN', 'https://private.example')
    with pytest.raises(ValueError, match='HTTPS'):
        cli.serve(argparse.Namespace(database='unused.sqlite', tailscale='100.80.216.26'))


def test_tailnet_login_and_csrf_keep_origin_checks(tmp_path):
    ip = '100.80.216.26'
    tailnet_origin = f'http://{ip}:8000'
    app = create_app(tmp_path/'db.sqlite', secret='s'*48, operator_token='o'*48,
                     origin='http://127.0.0.1:8000', allowed_hosts=['127.0.0.1', ip],
                     additional_origins=[tailnet_origin])
    endpoints = {route.path:route.endpoint for route in app.routes}
    login = endpoints['/operator/login']
    acknowledge = endpoints['/api/v1/alerts/{alert_id}/acknowledge']
    def request(origin, session, body='', csrf=None):
        headers = [(b'origin', origin.encode())]
        if csrf is not None:
            headers.append((b'x-csrf-token', csrf.encode()))
        req = Request({'type':'http', 'headers':headers, 'session':session})
        req._body = body.encode()
        return req
    for origin in ['http://127.0.0.1:8000', tailnet_origin]:
        session = {}
        with pytest.raises(HTTPException) as rejected:
            asyncio.run(login(request('http://attacker.invalid', session, 'o'*48)))
        assert rejected.value.status_code == 403
        with pytest.raises(HTTPException) as rejected:
            asyncio.run(login(request(origin, session, 'wrong')))
        assert rejected.value.status_code == 401
        result = asyncio.run(login(request(origin, session, 'o'*48)))
        assert session['operator'] is True
        csrf = result['csrf']
        assert endpoints['/operator/session'](request(origin, session)) == {'csrf':csrf}
        for bad_origin, bad_csrf in [(origin, None), ('http://attacker.invalid', csrf)]:
            with pytest.raises(HTTPException) as rejected:
                acknowledge(1, request(bad_origin, session, csrf=bad_csrf))
            assert rejected.value.status_code == 403
        # Valid authentication/CSRF reaches resource lookup, with no alert created.
        with pytest.raises(HTTPException) as missing:
            acknowledge(1, request(origin, session, csrf=csrf))
        assert missing.value.status_code == 404


def test_tailnet_host_validation_rejects_unlisted_host(tmp_path):
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app = create_app(tmp_path/'db.sqlite', secret='s'*48, operator_token='o'*48,
                     allowed_hosts=['127.0.0.1', '100.80.216.26'])
    config = next(item for item in app.user_middleware if item.cls is TrustedHostMiddleware)
    async def check(host):
        messages = []
        async def upstream(scope, receive, send):
            await send({'type':'http.response.start', 'status':200, 'headers':[]})
            await send({'type':'http.response.body', 'body':b''})
        async def receive():
            return {'type':'http.request', 'body':b''}
        async def send(message):
            messages.append(message)
        middleware = TrustedHostMiddleware(upstream, **config.kwargs)
        await middleware({'type':'http', 'headers':[(b'host', host.encode())]}, receive, send)
        return messages[0]['status']
    assert asyncio.run(check('100.80.216.26:8000')) == 200
    assert asyncio.run(check('127.0.0.1:8000')) == 200
    assert asyncio.run(check('attacker.invalid:8000')) == 400


def test_https_app_rejects_http_additional_origin(tmp_path):
    with pytest.raises(ValueError, match='HTTPS'):
        create_app(tmp_path/'db.sqlite', secret='s'*48, operator_token='o'*48,
                   origin='https://private.example', additional_origins=['http://100.80.216.26:8000'])
