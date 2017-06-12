#!/usr/bin/python

import socket
import time
import sys, traceback
import threading
import struct
import os
import pickle
from Crypto.Cipher import AES
from Crypto import Random
import shutil
import uuid
import tempfile
import io

sys.path.insert(0, '../TUDOIGUAL/tudoigual')
import chap
from x509.certs import *
from x509.ca import *
from ec.ec_elgamal import EC_ElGamal
from rsa.rsa import RSA_PKC, public_key_from_certificate
from utils.exceptions import *
from utils.ec_curves import *
from ec.gen import ECPoint, modInverse, bit_length

#TODO see if this works on mac
import tkinter as tk
from tkinter import messagebox
# from dialog import Dialog
conn = None
new_diff_cb = None

connected = False

diff_stack = {}
repos = {}
conditions = {}

g_AUTH = None
g_CRYP = None
g_server_AUTH = RSA_PKC(pub_in = public_key_from_certificate('server.pem'))

g_server_authenticate = True

g_authenticate = False
g_encrypt = False

thread_list = []

def run_thread(thr):
    thread_list.append(thr)
    thr.start()

def log(s):
    print(s)
    print(s, file = open(".log", "a"))


def save_obj(obj, name):
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name):
    try:
        with open(name + '.pkl', 'rb') as f:
            return pickle.load(f)
    except: return {}

def random_bytes(size):
    return Random.new().read(size)

def clientthread(conn):
    try:
        while True:
            #Receiving from server
            data = server_recv()
            if data == b'\0': continue
            if not data: continue
                # break
            event_received(data)
    except:
        traceback.print_exc(file=sys.stdout)

    log('socket closing')
    conn.close()

def clientbeat():
    global connected
    while True:
        log('h')
        if connected:
            server_send(['t'])
        time.sleep(1)

def bytes_to_file(b, out = tempfile.mktemp(suffix='pync_')):
    with open(out, 'wb') as f:
        f.write(b)
    return out

def file_to_bytes(file_name):
    try:
        with open(file_name, 'rb') as in_file:
            return in_file.read()
    except:
        return None

def get_certificate(name, org):
    global g_AUTH
    cert = file_to_bytes('cert.pem')
    if not cert:
        print('No certificate, requesting to server.')
        g_AUTH = RSA_PKC(gen = True)

        csr('.keys/sk-and-pk.pem', '/CN=' + name + '/O=' + org, out = 'cert.csr')
        csr_file = file_to_bytes('cert.csr')
        if csr_file:
            cert = server_request(['new_certificate', csr_file])[0]
            print('Got certificate from server')
            bytes_to_file(cert, 'cert.pem')
            return cert
        else:
            print('Failed to create cert request.')

    else:
        g_AUTH = RSA_PKC()

    return cert
        
def certify_challenge(nonce, enc_secret):
    global g_AUTH
    auth = chap.CHAP(rsa_priv = g_AUTH)
    return [auth.response(nonce, enc_secret)]

def certify_server(name, org):
    global g_AUTH
    global g_server_AUTH
    global g_authenticate

    cert = get_certificate(name, org)

    server_chap = chap.CHAP(rsa_pub = g_server_AUTH)

    res = server_request(['certify_challenge', cert] + server_chap.challenge())

    g_authenticate = True

    if res[0] == b'fail':
        print('Failed to get certified by server.')
        sys.exit(1)

    if not server_chap.verify(res[0]):
        print('Server not authenticated')
        sys.exit(1)


def get_secure_connection():

    ECC = EC_ElGamal()
    server_pk = server_request(['key_exchange', str(ECC.pk.x), str(ECC.pk.y)])

    ECC.set_pkB(assert_num(server_pk[0]), assert_num(server_pk[1]))

    def toggle_encryption():
        global g_CRYP
        g_CRYP = ECC

    server_request(['encrypt_connection'],
            toggle_encryption)




def server_connect(ip, port, cb, name, org):
    try:
        global new_diff_cb
        global conn
        global connected
        load_repos()

        new_diff_cb = cb

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        try:
            remote_ip = socket.gethostbyname(ip)
        except socket.gaierror:
            #could not resolve
            log('Hostname could not be resolved. Exiting')
            sys.exit()

        conn.connect((remote_ip, port))

        run_thread(threading.Thread(target = clientthread, args = (conn,)))
        # run_thread(threading.Thread(target = clientbeat))

        certify_server(name, org)
        get_secure_connection()

        connected = True
        
    except:
        traceback.print_exc(file=sys.stdout)

    
def read_arg(f):
    lb = f.read(4)
    if not lb: return b'', None
    l = struct.unpack('>I', lb)[0]
    m = f.read(l)
    if not m: return b'', None
    return lb + m, bytes(m)

def server_recv():
    global conn
    global g_CRYP
    global g_server_authenticate

    msgs = []

    signed = False
    signature = None

    msg = b''

    f = conn.makefile('rb')

    START = f.read(1)
    if not START: return None

    if g_CRYP:
        b, YX = read_arg(f)
        b, YY = read_arg(f)
        b, iv = read_arg(f)
        b, ciphertext = read_arg(f)
        b, salt = read_arg(f)
        b, tag = read_arg(f)
        msg = g_CRYP.decrypt(ECPoint(assert_num(YX), assert_num(YY),
            g_CRYP.ec), iv, ciphertext, salt, tag)

        f = io.BytesIO(msg)

    num = f.read(4)
    msg += num

    if not num: return num
    num = struct.unpack('>I', num)[0]

    for i in range(num):
        b, m = read_arg(f)
        msg += b
        msgs.append(m)

    if not g_CRYP and g_server_authenticate:
        b, signature = read_arg(f)
        if not g_server_AUTH.verify(msg, signature):
            print('Client failed to verify message')
            return b'\0'

    return msgs

def assert_num(s):
    if s is None: return None
    if isinstance(s, int): return s
    try:
        return struct.unpack('>i', s)[0]
    except:
        return int(s)

def assert_byte(s):
    if isinstance(s, int):
        try:
            s = struct.pack('>i', s)
        except:
            s = str(s)
    if isinstance(s, str): s = str.encode(s)
    return s

def strings_to_bytes(strings):
    arr = []
    for s in strings:
        arr.append(assert_byte(s))
    return arr

def server_request(msgs, after_send = None):
    msgs = strings_to_bytes(msgs)
    # req_code = random_bytes(16)
    req_code = bytes(uuid.uuid4().hex, 'ascii')
    msgs[0] += b':' + req_code

    # thr_id = threading.get_ident() 
    conditions[req_code] = cond = {'res': None, 'cond': threading.Lock()}

    server_send(msgs)

    if after_send is not None: after_send()

    cond['cond'].acquire()
    while cond['res'] is None:
        cond['cond'].acquire()
    del conditions[req_code]

    return cond['res']

def append_arg(s):
    s = assert_byte(s)
    return struct.pack('>I', len(s)) + s

def server_send(msgs):
    global conn
    global g_AUTH
    global g_CRYP
    global g_authenticate
    msg = b''

    for s in msgs:
        msg += append_arg(s)

    msg = struct.pack('>I', len(msgs)) + msg

    if g_CRYP:
        Y, iv, ciphertext, salt, tag = g_CRYP.encrypt(msg)
        msg = b''
        msg += append_arg(str(Y.x))
        msg += append_arg(str(Y.y))
        msg += append_arg(iv)
        msg += append_arg(ciphertext)
        msg += append_arg(salt)
        msg += append_arg(tag)

    elif g_authenticate:
        sig = g_AUTH.sign(msg)
        msg += append_arg(sig)

    conn.sendall(b'S' + msg)

def server_new_diff(repo_name, diff):
    try:
        log("Changes on repo " + repo_name + " " + str(diff))
        repo = repos[repo_name]

        previous_cypher = None

        if repo['diffs']:
            previous_cypher = repo['diffs'][-1][-16:]
        else:
            previous_cypher = repo['iv']


        cipher = AES.new(repo['repo_key'], AES.MODE_CBC, previous_cypher)

        # enc_diff = b''
        last_cypher = None
        # for i in range(0, len(diff), 16):
            # diff_block = pad(diff[i:i+16], 16)
            # last_cypher = cipher.encrypt(diff_block)
            # enc_diff += last_cypher
            # print(last_cypher)
        enc_diff = cipher.encrypt(pad(diff, 16))
        last_cypher = enc_diff[-16:]

        repo['diffs'].append(enc_diff)

        save_repos()

        server_send(["new_diff", repo_name, enc_diff])
    except:
        traceback.print_exc(file=sys.stdout)

def pad(s, bs = 16):
    return s + (bs - len(s) % bs) * b'\0'

def server_listen_repo(repo_name, repo_dir):

    if repo_name not in repos:
        repos[repo_name] = {
            'repo_name': repo_name,
            'dir': repo_dir,
            'repo_key': b'',
            'diffs': [], 'iv': b''
        }
        save_repos()

    res = server_request(['listen_to_repo', repo_name])
    if res[0] == b'success': #PERMISSION GRANTED
        log('Access granted.')
        server_send(['get_me_updated', repo_name, len(repos[repo_name]['diffs'])])
    else:
        res = server_request(['req_key', repo_name])
        print(res)
        grant_key(repo_name, *res)


def remove_contents(directory):
    try:
        for the_file in os.listdir(folder):
            file_path = os.path.join(folder, the_file)
            if os.path.isfile(file_path):
                os.unlink(file_path)
    except:
        pass

def grant_key(repo_name = None, enc_key = None, iv = None):
    global g_AUTH
    repo_name = assert_str(repo_name)

    if enc_key is None or repo_name is None:
        print('Invalid key grant response')
        return

    if enc_key == b'queue':
        print('No client with key online to grant.')
        return

    if iv is not None and enc_key != b'denied': # KEY GRANTED
        print('Key granted!')
        repo = repos[repo_name]
        repo['repo_key'] = g_AUTH.decrypt(enc_key)
        repo['iv'] = iv
        repo['diffs'] = []
        try:
            # shutil.rmtree(repo['dir'])
            remove_contents(repo['dir'])
        except:
            pass
        save_repos()
        server_listen_repo(repo_name, repo['dir'])
    else:
        print('Permission not granted')



def assert_str(s):
    if s is None: return None
    if isinstance(s, str): return s
    return s.decode('ascii')

def server_req_key(repo_name):
    res = server_request(["req_key", repo_name])
    log(str(res))


def req_key(repo_name, certificate):
    log('REQUEST FOR KEY')
    repo_name = repo_name.decode('ascii')
    repo = repos[repo_name]

    requester_cert = bytes_to_file(certificate)

    # TODO: certificate instead of public_key?
    # d = Dialog(dialog="dialog")

    cipher = RSA_PKC(pub_in = public_key_from_certificate(requester_cert))
    enc_key = cipher.encrypt(repo['repo_key'])

    # result = d.yesno("Do you want to grant " + repo_name + " to client " + str(public_key) + "?") == d.OK
    result = messagebox.askokcancel("Grant key", "Do you want to grant "
            + repo_name + " to client " + str(certificate) + "?",
            icon='warning')

    if result: return [enc_key, repo['iv']]

    return ['denied']

def save_repos():
    save_obj(repos, 'repos')

def load_repos():
    global repos
    repos = load_obj('repos')


def create_repo(repo_name, access_key):
    log('Registering repo')
    repo_name = repo_name.decode('ascii')
    repo = repos[repo_name]

    repo['iv'] = random_bytes(16)
    repo['diffs'] = []
    repo['repo_key'] = random_bytes(32)
    save_repos()

    cipher = AES.new(repo['repo_key'], AES.MODE_ECB)
    enc_access_key = cipher.encrypt(access_key)
    #TODO add salt
    
    return [enc_access_key, repo['iv']]

def t():
    log('.')

def new_diff(repo_name, enc_diff):
    repo_name = repo_name.decode('ascii')
    repo = repos[repo_name]
    if 'diffs' not in repo: repo['diffs'] = []

    previous_cypher = None

    if repo['diffs']:
        previous_cypher = repo['diffs'][-1][-16:]
    else:
        previous_cypher = repo['iv']

    cipher = AES.new(repo['repo_key'], AES.MODE_CBC, previous_cypher)

    repo['diffs'].append(enc_diff)
    save_repos()

    diff = cipher.decrypt(enc_diff)

    # global new_diff_cb
    if new_diff_cb:
        new_diff_cb(repo_name, diff)

def check_access(repo_name, enc_access_key):
    try:
        log('checking access')
        repo_name = repo_name.decode('ascii')

        repo = repos[repo_name]

        if repo['repo_key'] == b'': return ['no key']

        cipher = AES.new(repo['repo_key'], AES.MODE_ECB)
        access_key = cipher.decrypt(enc_access_key)

        return [access_key]
    except:
        traceback.print_exc(file=sys.stdout)

events = {
    "t": t,
    "new_diff": new_diff,
    "req_key": req_key,
    "grant_key": grant_key,
    "create_repo": create_repo,
    "certify_challenge": certify_challenge,
    "check_access": check_access
}

def event_thread(data):
    try:
        evargs = data[0].split(b':', 1)
        event = None
        req_id = None
        if evargs and len(evargs) > 1:
            event = evargs[0].decode('ascii')
            req_id = evargs[1]
        else:
            event = data[0].decode('ascii')

        if event in events:
            res = events[event](*data[1:])
            if req_id:
                if res is None: res = ['']
                server_send([b':' + req_id] + res)
        else:
            log("Event " + event + " does not exist!")
    except:
        traceback.print_exc(file=sys.stdout)

def event_received(data):
    try:
        if data[0][0] == b':'[0]:
            req_id = data[0][1:]
            if req_id in conditions:
                cond = conditions[req_id]
                cond['res'] = data[1:]
                cond['cond'].release()
        else:
            run_thread(threading.Thread(target = event_thread, args = (data,)))
    except:
        traceback.print_exc(file=sys.stdout)


def main():
    global thread_list
    ROOT = tk.Tk()
    ROOT.withdraw()
    ROOT.mainloop()

    while thread_list:
        try:
            p = thread_list.pop(0)
            p.join()
        except:
            traceback.print_exc(file=sys.stdout)

# time.sleep(10)
