from __future__ import print_function
import socket, threading, struct, sys, select, errno

HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9053
QUIET = True  # opsec: no stdout noise by default

def log(*a):
    if not QUIET:
        print(*a, file=sys.stderr)

def recvn(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError('peer closed')
        buf += chunk
    return buf

def reply(sock, code, atyp=0x01):
    sock.sendall(struct.pack('!BBBB', 0x05, code, 0x00, atyp) + b'\x00\x00\x00\x00\x00\x00')

def handle(client):
    remote = None
    try:
        client.settimeout(15)
        ver, nmethods = struct.unpack('!BB', recvn(client, 2))
        recvn(client, nmethods)  # discard offered methods, we only do no-auth
        client.sendall(b'\x05\x00')

        ver, cmd, _, atyp = struct.unpack('!BBBB', recvn(client, 4))
        if atyp == 0x01:
            addr = socket.inet_ntoa(recvn(client, 4))
        elif atyp == 0x03:
            n = struct.unpack('!B', recvn(client, 1))[0]
            addr = recvn(client, n).decode()
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, recvn(client, 16))
        else:
            reply(client, 0x08)  # address type not supported
            return
        port = struct.unpack('!H', recvn(client, 2))[0]

        if cmd != 0x01:  # only CONNECT
            reply(client, 0x07)
            return

        try:
            remote = socket.create_connection((addr, port), timeout=10)
        except socket.timeout:
            reply(client, 0x06)  # TTL expired
            return
        except socket.gaierror:
            reply(client, 0x04)  # host unreachable (DNS failed)
            return
        except socket.error as e:
            code = {
                errno.ECONNREFUSED: 0x05,
                errno.ETIMEDOUT: 0x06,
                errno.EHOSTUNREACH: 0x04,
                errno.ENETUNREACH: 0x03,
            }.get(e.errno, 0x01)
            reply(client, code)
            return

        client.settimeout(None)
        reply(client, 0x00)
        log('relay ->', addr, port)
        pump(client, remote)
    except Exception as e:
        log('handshake error:', e)
    finally:
        for s in (client, remote):
            if s:
                try: s.close()
                except Exception: pass

def pump(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 300)
            if x:
                break
            if not r:
                break  # idle timeout
            for s in r:
                other = b if s is a else a
                try:
                    data = s.recv(4096)
                except socket.error:
                    return
                if not data:
                    return
                other.sendall(data)
    except Exception as e:
        log('pump error:', e)

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    log('listening on %s:%d' % (HOST, PORT))
    try:
        while True:
            client, _ = srv.accept()
            t = threading.Thread(target=handle, args=(client,))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()

if __name__ == '__main__':
    main()
