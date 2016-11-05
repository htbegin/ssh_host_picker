#!/usr/bin/env python
# -*- coding: ascii -*-

import sys
import os
import string
import pexpect
import argparse
import re
import subprocess
import time
from multiprocessing import Process, Pipe
import signal

CONT = "(?i)are you sure you want to continue connecting"
PASSWD = "(?i)password:"
PERM = "(?i)permission denied"
CLOSE = "(?i)connection closed by remote host"
KEY_VERIFY_ERR = "(Host key verification failed)|ssh_exchange_identification"
P_TIMEOUT = pexpect.TIMEOUT
P_EOF = pexpect.EOF

def handle_passwd(child, srv, port, passwd):
    conn, err = None, True

    child.sendline(passwd)
    idx = child.expect([PASSWD, P_TIMEOUT], timeout=5)
    if idx == 0:
        handle_error(child, srv, port, "invalid passwd")
    elif idx == 1:
        print "connect to %s:%d" % (srv, port)
        return child, False
    else:
        handle_error(child, srv, port, "unknown error")

    return conn, err

def handle_error(child, srv, port, detail):
    print "connect %s:%d %s" % (srv, port, detail)
    child.close()

def connect_to_ssh_server(srv, port, cmd, user, passwd, timeout, ob_key):
    conn, err = None, True
    cmd = "%s " \
          "-Z %s %s@%s -N -p %d -D 2222 -o TCPKeepAlive=yes -o ServerAliveCountMax=3 " \
          "-o ServerAliveInterval=20" % (cmd, ob_key, user, srv, port)

    child = pexpect.spawn(cmd)
    idx = child.expect([PASSWD, CONT, KEY_VERIFY_ERR, P_TIMEOUT, P_EOF], timeout=timeout)
    if idx == 0:
        return handle_passwd(child, srv, port, passwd)
    elif idx == 1:
        child.sendline("yes")
        idx = child.expect([PASSWD, P_TIMEOUT, P_EOF], timeout=timeout/2)
        if idx == 0:
            return handle_passwd(child, srv, port, passwd)
        elif idx == 1:
            handle_error(child, srv, port, "timeouted")
        elif idx == 2:
            handle_error(child, srv, port, "closed")
        else:
            handle_error(child, srv, port, "unexpected error")
    elif idx == 2:
        handle_error(child, srv, port, "invalid known_hosts")
    elif idx == 3:
        handle_error(child, srv, port, "timeouted")
    elif idx == 4:
        handle_error(child, srv, port, "closed")
    else:
        handle_error(child, srv, port, "unexpected error")

    return conn, err

def pick_ssh_server(srv_list, cmd, user, passwd, timeout, ob_key):
    srv_idx, srv_conn = 0, None

    for srv_idx, srv_port_tuple in enumerate(srv_list):
        srv, port = srv_port_tuple
        conn, err = connect_to_ssh_server(srv, port, cmd, user, passwd, timeout, ob_key)
        if not err:
            srv_conn = conn
            break

    return srv_idx, srv_conn

def gen_server_list(srv_name_list, srv_port):
    port_list = [int(x) for x in srv_port.split(",")]
    srv_list = [(x, y) for x in srv_name_list for y in port_list]

    return srv_list

def single_id(id_str):
    if id_str in string.ascii_lowercase or id_str in string.ascii_uppercase:
        return id_str
    else:
        try:
            sid = int(id_str, 0)
        except ValueError:
            pass
        else:
            return str(sid)

    return None

def pair_id(pair):
    start_str, end_str = pair

    for s in (string.ascii_lowercase, string.ascii_uppercase):
        if start_str in s and end_str in s and start_str < end_str:
            start_ofs = ord(start_str) - ord(s[0])
            end_ofs = ord(end_str) - ord(s[0])
            return s[start_ofs:end_ofs+1]

    try:
        sid = int(start_str, 0)
        eid = int(end_str, 0)
    except ValueError:
        pass
    else:
        if sid < eid:
            return [str(e) for e in range(sid, eid+1)]

    return None

# [12,X-Z,a,1-6]"
def parse_c_seq(c_input):
    c_seq = []
    for e in c_input.split(","):
        got_id = False
        pair = e.split("-")
        if 1 == len(pair):
            sid = single_id(pair[0])
            if sid is not None:
                c_seq.append(sid)
                got_id = True
        elif 2 == len(pair):
            pid = pair_id(pair)
            if pid is not None:
                c_seq.extend(pid)
                got_id = True

        if not got_id:
            print "invalid desc %s" % e

    uniq_c_order_set = []
    for c in c_seq:
        if c not in uniq_c_order_set:
            uniq_c_order_set.append(c)

    return uniq_c_order_set

def expand_server_desc(desc):
    left_bracket = desc.find("[")
    if -1 == left_bracket:
        return [desc]
    right_bracket = desc.find("]", left_bracket + 1)
    if -1 == right_bracket:
        return [desc]

    c_seq = parse_c_seq(desc[left_bracket+1:right_bracket])

    prefix = desc[:left_bracket]
    suffix = desc[right_bracket+1:]

    if not c_seq:
        return ["".join((prefix, suffix))]

    server_list = []
    for c in c_seq:
        server = "".join((prefix, c, suffix))
        server_list.extend(expand_server_desc(server))

    return server_list

def parse_server_list_line(line):
    server_list = []
    for desc in line.split(";"):
        server_list.extend(expand_server_desc(desc))
    return server_list

def arg_to_server_list(server_arg):
    server_list = []
    if os.path.isfile(server_arg):
        with open(server_arg, "rb") as fd:
            for line in fd:
                server_list.extend(parse_server_list_line(line))
    else:
        server_list.extend(parse_server_list_line(server_arg))
    return server_list

def sort_server_list(conn):
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    def ping_time(srv_name):
        rtt = 10000

        try:
            ping = subprocess.Popen(["ping", "-q", "-n", "-c 3", srv_name], stdout=subprocess.PIPE)
            output = ping.communicate()[0]
        except Exception:
            if debug:
                sys.stdout.write("#exec ping on %s failed\n" % srv_name)
            return rtt

        if output:
            #rtt min/avg/max/mdev = 197.950/198.276/198.800/0.635 ms
            m = re.search("=\s*\d+(\.\d+)?/(?P<avg>\d+(\.\d+)?)", output)
            if m is not None:
                rtt = int(float((m.group("avg"))))

        if debug:
            sys.stdout.write("#rtt for %s is %d\n" % (srv_name, rtt))

        return rtt

    srv_name_list, debug = conn.recv()
    if debug:
        sys.stdout.write("#got server list:\n  %s\n" % "\n  ".join(srv_name_list))
    srv_name_list.sort(key=ping_time)
    conn.send(srv_name_list)
    conn.close()
    return 0

def get_cfg_fpath():
    return os.path.expanduser(os.path.join("~", ".ssh_picker"))

def is_srv_list_file_expired(fpath):
    expired = True
    try:
        result = os.stat(fpath)
    except OSError:
        pass
    else:
        f_mtime_sec = result.st_mtime
        now_sec = time.time()
        if now_sec - f_mtime_sec < 72 * 3600:
            expired = False
    return expired

def load_srv_list_from_file(fpath):
    try:
        with open(fpath) as fd:
            return [srv.rstrip("\n") for srv in fd]
    except IOError:
        pass

    return None

if __name__ == "__main__":
    parse = argparse.ArgumentParser(description="ssh picker")
    parse.add_argument("-u", "--user", action="store", help="username", required=True)
    parse.add_argument("-p", "--passwd", action="store", help="password", required=True)
    parse.add_argument("-k", "--key", action="store", help="key", required=True)
    parse.add_argument("-c", "--cmd", action="store", help="ssh cmd path", required=True)
    parse.add_argument("-s", "--server", action="store", help="all server list",
                       required=True, type=arg_to_server_list)
    parse.add_argument("-o", "--only", action="store", default=None,
                       help="only used these servers", type=arg_to_server_list)
    parse.add_argument("-l", "--port", action="store", default="22,80", help="port selection")
    parse.add_argument("-t", "--timeout", action="store", default=8, help="connection timeout", type=int)
    parse.add_argument("-f", "--force", action="store_true", help="regenerate server list")
    parse.add_argument("-d", "--debug", action="store_true", help="turn on debug msg")
    opt = parse.parse_args()

    user = opt.user
    passwd = opt.passwd
    ob_key = opt.key
    cmd = opt.cmd
    timeout = opt.timeout

    if not os.path.exists(cmd):
        parse.print_help()
        sys.exit(1)

    srv_name_list = opt.server
    if opt.only is not None:
        srv_name_list = opt.only

    if opt.debug:
        sys.stdout.write("#server list: %s\n" % srv_name_list)
        sys.stdout.write("#port list: %s\n" % opt.port)

    checker = None
    cached_srv_name_list = load_srv_list_from_file(get_cfg_fpath())
    if not opt.force and cached_srv_name_list is not None and \
       not is_srv_list_file_expired(get_cfg_fpath()) and \
       set(cached_srv_name_list) == set(srv_name_list) and opt.only is None:
        srv_name_list = cached_srv_name_list
    elif opt.only is None:
        # check ping check process
        sys.stdout.write("#re-generate server list cache\n")
        checker_conn, child_conn = Pipe()
        checker = Process(target=sort_server_list, args=(child_conn,))
        checker.start()
        checker_conn.send((srv_name_list, opt.debug))

        if cached_srv_name_list is not None:
            srv_name_list = cached_srv_name_list

    srv_list = gen_server_list(srv_name_list, opt.port)

    skip = [False]
    def advance_to_next_server(signum, frame):
        sys.stdout.write("#skip the current server...\n")
        skip[0] = True
    signal.signal(signal.SIGINT, advance_to_next_server)

    idx = 0
    while idx < len(srv_list):
        ofs, conn = pick_ssh_server(srv_list[idx:], cmd, user, passwd, timeout, ob_key)
        idx += ofs

        if conn is not None:
            while conn.isalive():
                if checker is not None and not checker.is_alive():
                    sorted_srv_name_list = checker_conn.recv()
                    if opt.debug:
                        sys.stdout.write("#got sorted server list\n  %s\n" % "\n  ".join(sorted_srv_name_list))
                    checker.join()
                    checker = None

                    with open(get_cfg_fpath(), "wb") as fd:
                        fd.write("\n".join(sorted_srv_name_list))
                        fd.write("\n")

                    if srv_list[idx] in sorted_srv_name_list[:3]:
                        sys.stdout.write("#reconnection is not needed\n")
                    else:
                        srv_list = gen_server_list(sorted_srv_name_list, opt.port)
                        idx = -1
                        sys.stdout.write("#reconnect by server ping result\n")
                        break

                if skip[0]:
                    skip[0] = False
                    break

                time.sleep(1)

            conn.terminate(True)

        idx += 1

    sys.exit(0)

