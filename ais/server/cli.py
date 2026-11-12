import argparse
from contextlib import ExitStack
import ipaddress
import os
import secrets
import socket
import subprocess
from ais.contracts import bounded_text
from ais.server.storage import Store


def tailscale_address(value):
    if value == 'auto':
        result = subprocess.run(['tailscale', 'ip', '-4'], check=True,
                                capture_output=True, text=True, timeout=5)
        value = result.stdout.strip()
    address = ipaddress.IPv4Address(value)
    if address not in ipaddress.IPv4Network('100.64.0.0/10'):
        raise ValueError('Expected this machine\'s Tailscale IPv4 address (100.64.0.0/10)')
    return str(address)


def serve(args):
    import uvicorn
    from ais.server.app import create_app

    addresses = ['127.0.0.1']
    hosts = [h.strip() for h in os.environ.get('AIS_ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') if h.strip()]
    extra_origins = []
    if args.tailscale:
        address = tailscale_address(args.tailscale)
        # Preserve Secure cookies for existing HTTPS-only deployments.
        if os.environ.get('AIS_OPERATOR_ORIGIN', '').startswith('https:'):
            raise ValueError('An HTTPS operator origin is configured; use an HTTPS Tailscale reverse proxy instead')
        addresses.append(address)
        hosts.append(address)
        extra_origins.append(f'http://{address}:8000')

    with ExitStack() as stack:
        listeners = []
        for address in addresses:
            listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, 8000))
            listener.listen(2048)
            listener.setblocking(False)
            listeners.append(listener)
        app = create_app(db_path=args.database, allowed_hosts=hosts,
                         additional_origins=extra_origins)
        server = uvicorn.Server(uvicorn.Config(app, workers=1, access_log=False))
        server.run(sockets=listeners)


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description='Private monitoring server operations')
    p.add_argument('--database',default=os.environ.get('AIS_DATABASE','var/server.sqlite'))
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('secrets')
    add=sub.add_parser('register'); add.add_argument('name'); add.add_argument('host')
    rotate=sub.add_parser('rotate'); rotate.add_argument('agent_id')
    disable=sub.add_parser('disable'); disable.add_argument('agent_id')
    backup=sub.add_parser('backup'); backup.add_argument('destination')
    serving = sub.add_parser('serve')
    serving.add_argument('--tailscale', nargs='?', const='auto',
                         default=os.environ.get('AIS_TAILSCALE_IP') or None,
                         metavar='IP', help='Also listen on the Tailscale IPv4 address; detect it when IP is omitted')
    args=p.parse_args()
    if args.command=='secrets':
        print('AIS_SERVER_SECRET='+secrets.token_urlsafe(48))
        print('AIS_OPERATOR_TOKEN='+secrets.token_urlsafe(48))
        return
    if args.command=='serve':
        try:
            serve(args)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            p.error(f'Could not start server: {exc}')
        return
    store=Store(args.database)
    if args.command=='register':
        bounded_text(args.host); bounded_text(args.name)
        agent,token=store.provision(args.name,args.host)
        print('Agent: '+agent+'\nToken (shown once): '+token)
    elif args.command=='rotate':
        print('Token (shown once): '+store.rotate(args.agent_id))
    elif args.command=='disable':
        with store.connect() as db:
            if not db.execute('UPDATE agents SET enabled=0 WHERE id=?',(args.agent_id,)).rowcount:
                p.error('unknown agent')
    elif args.command=='backup':
        store.backup(args.destination)

if __name__=='__main__':
    main()
