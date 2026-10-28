#!/usr/bin/env python3
import json, os, socket, subprocess

SOCK='/run/snat-wg-peer.sock'
HELPER='/usr/local/sbin/snat-wg-peer'

try: os.unlink(SOCK)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(SOCK); os.chmod(SOCK, 0o660)
try:
    import pwd, grp
    os.chown(SOCK, pwd.getpwnam('snat-web').pw_uid, grp.getgrnam('snat-web').gr_gid)
except Exception: pass
s.listen(16)
while True:
    conn,_=s.accept()
    with conn:
        try:
            data=conn.recv(8192)
            req=json.loads(data.decode())
            if req.get('op') != 'add': raise ValueError('unsupported operation')
            args=[HELPER,'add',str(req['name']),str(req['public_key']),str(req['agent_ip'])]
            p=subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
            out={'success':p.returncode == 0, 'error':(p.stderr or p.stdout)[-500:]}
        except Exception as exc:
            out={'success':False,'error':str(exc)[:500]}
        conn.sendall((json.dumps(out,separators=(',',':'))+'\n').encode())
