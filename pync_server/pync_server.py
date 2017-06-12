#!/usr/bin/python

import uuid
import socket
import sys, traceback
import threading
import struct
import pickle
import tempfile
import time
from Crypto import Random
from Crypto.Cipher import AES
import io

sys.path.insert(0, '../TUDOIGUAL/tudoigual')
import chap
from x509.certs import *
from x509.ca import *
from ec.ec_elgamal import EC_ElGamal
from utils.exceptions import *
from utils.ec_curves import *
from rsa.rsa import RSA_PKC, public_key_from_certificate
from ec.gen import ECPoint, modInverse, bit_length

repos = {}
clients = {}

g_AUTH = RSA_PKC(key_in = 'CA/rsa/server.key',
        pub_in = public_key_from_certificate('CA/rsa/0000_cert.pem'))

def pad(s, bs = 16):
    return s + (bs - len(s) % bs) * b'\0'

def t(client):
    print('.')

def file_to_bytes(file_name):
    try:
        with open(file_name, 'rb') as in_file:
            return in_file.read()
    except:
        return None

def assert_byte(s):
    if isinstance(s, int):
        try:
            s = struct.pack('>i', s)
        except:
            s = str(s)
    if isinstance(s, str): s = str.encode(s)
    return s

def append_arg(s):
    s = assert_byte(s)
    return struct.pack('>I', len(s)) + s

def bytes_to_file(b, out = tempfile.mktemp(suffix='pync_')):
    with open(out, 'wb') as f:
        f.write(b)
    return out

def assert_str(s):
    if s is None: return None
    if isinstance(s, str): return s
    return s.decode('ascii')

def assert_num(s):
    if s is None: return None
    if isinstance(s, int): return s
    try:
        return struct.unpack('>i', s)[0]
    except:
        return int(s)

def random_bytes(size):
    return Random.new().read(size)

def req_key(client, repo_name):
    repo_name = repo_name.decode('ascii')
    repo = get_repo(repo_name)
    print("client " + client.unique_id + " requested key to " + str(repo_name))
    if repo:
        return repo.request_key(client)



def save(obj, name):
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load(name):
    try:
        with open(name + '.pkl', 'rb') as f:
            return pickle.load(f)
    except: return {}

def save_repos():
    state = {k:repo.get_state() for (k,repo) in repos.items()}
    save(state, 'repos')

def load_repos():
    global repos
    state = load('repos')
    for (k,state) in state.items():
        repos[k] = Repo(k)
        repos[k].set_state(state)

class Repo:
    def __init__(self, repo_name, client = None):
        self.name = repo_name
        self.diffs = []
        self.complete = False
        self.iv = None

        self.clients = {}
        self.enc_access_key = ''
        self.access_key = ''
        self.request_queue = []

        repos[repo_name] = self
        self.access_key = random_bytes(32)

        if client:
            print('New repo')
            self.clients[client.unique_id] = client
            self.creator_id = client.unique_id
            res = client.request(['create_repo', repo_name, self.access_key])
            if res and len(res) > 1:
                self.enc_access_key = res[0]
                self.complete = True
                self.iv = res[1]
                save_repos()

    def get_state(self):
        state = self.__dict__.copy()
        del state['clients']
        return state

    def set_state(self, d):
        self.__dict__.update(d)
    

    def request_key(self, client, online_client = None):
        if client.unique_id in self.request_queue:
            self.request_queue.remove(client.unique_id)

        if not online_client:
            for i, c in self.clients.items():
                if c.connected:
                    online_client = c

        if online_client:
            print('Sending request to client ' + c.unique_id)
            return online_client.request(['req_key', self.name, client.certificate]) # TODO: send certificate

        self.request_queue.append(client.unique_id)
        return ['queue']

    def was_created_by(self, client):
        return client.unique_id == self.creator_id

    def new_diff(self, diff, client):
        if client.unique_id not in self.clients:
            print('client access to repo not authenticated')
            return
        print('Client pushed new diff')

        self.diffs.append(diff)
        save_repos()

        self.broadcast(['new_diff', self.name, diff], client)

    def update_client_list(self):
        self.clients = {k:client for (k,client) in self.clients.items() if client.connected}

    def broadcast(self, message, exclude = None):
        self.update_client_list()
        for uid, watcher in self.clients.items():
            if exclude is None or (watcher != exclude and uid != exclude.unique_id):
                watcher.send(message)

    def update_queue(self, online_client = None):
        while self.request_queue:
            uid = self.request_queue[0]
            requester = clients[uid]
            if uid in clients and requester.connected:
                answer = self.request_key(requester, online_client)
                requester.send(['grant_key', self.name] + answer)

    def check_access(self, client):
        res = client.request(["check_access", self.name, self.enc_access_key])
        if res and len(res) > 0 and self.access_key == res[0]:
            # Adding client to broadcast list
            self.clients[client.unique_id] = client
            print('Access granted')
            self.update_queue()
            return True
        else:
            print('Access not granted')
            return False

def get_repo(repo_name):
    if repo_name in repos:
        return repos[repo_name]

    return None

def new_diff(client, repo_name, diff):
    repo = get_repo(repo_name.decode('ascii'))

    if repo is None: return None

    repo.new_diff(diff, client)


def listen_to_repo(client, repo_name):
    if repo_name is None or not client.connected: return ["failure"]
    repo_name = repo_name.decode('ascii')

    print(client.unique_id + ' trying to listen to ' + repo_name)

    repo = get_repo(repo_name)

    if repo is None:
        Repo(repo_name, client)
        return ["success"]
    elif repo.check_access(client):
        return ["success"]
    return ["failure"]

def certify_challenge(client, client_cert_bytes, nonce, enc_secret):
    client_cert = bytes_to_file(client_cert_bytes)

    client.AUTH = RSA_PKC(pub_in = public_key_from_certificate(client_cert))

    client_chap = chap.CHAP(rsa_pub = client.AUTH)

    server_chap = chap.CHAP(rsa_priv = g_AUTH)

    client.certificate = client_cert_bytes

    res = client.request(['certify_challenge'] + client_chap.challenge())

    if not client_chap.verify(res[0]):
        print('Client failed to authenticate')
        return ['fail']

    clients[client.unique_id] = client
    client.connected = True
    client.authenticate = True

    return [server_chap.response(nonce, enc_secret)]


def get_me_updated(client, repo_name, num_diffs):
    repo_name = assert_str(repo_name)
    num_diffs = assert_num(num_diffs)
    repo = get_repo(repo_name)

    for i in range(num_diffs, len(repo.diffs)):
        client.send(['new_diff', repo.name, repo.diffs[i]])


    if client in repo.clients:
        repo.update_queue(client)

def new_certificate(client, csr_file):
    print('Client requesting certificate')
    csr_tmp = bytes_to_file(csr_file)
    out_tmp = tempfile.mktemp(suffix = 'cert')

    sign_csr(csr = csr_tmp,
            ca_cert = 'CA/rsa/0000_cert.pem',
            ca_key = 'CA/rsa/server.key',
            out = out_tmp)
    cert = file_to_bytes(out_tmp)
    if not cert:
        print('Failed to create certificate for client.')
        return ['fail']
    return [cert]

def encrypt_connection(client):
    client.CRYP = client.elgamal

    print('Secure connection initiated.')
    return ['True']

def key_exchange(client, client_pk_x, client_pk_y):
    client.elgamal = EC_ElGamal()
    client.elgamal.set_pkB(assert_num(client_pk_x), assert_num(client_pk_y))

    return [str(client.elgamal.pk.x), str(client.elgamal.pk.y)]

def client_print(client, message):
    print(message)

events = {
    "t": t,
    "print": client_print,
    "req_key": req_key,
    "new_diff": new_diff,
    "get_me_updated": get_me_updated,
    "new_certificate": new_certificate,
    "key_exchange": key_exchange,
    "encrypt_connection": encrypt_connection,
    "certify_challenge": certify_challenge,
    "listen_to_repo": listen_to_repo
}

def strings_to_bytes(strings):
    arr = []
    for s in strings:
        arr.append(assert_byte(s))
    return arr

def event_thread(client, data):
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
            data[0] = client
            res = events[event](*data)
            if res is None: res = ['']
            if req_id:
                client.send([b':' + req_id] + res)
        else:
            print("Event " + event + " does not exist!")
    except Exception as e:
        traceback.print_exc(file=sys.stdout)

def event_received(client, data):

    if data[0][0] == b':'[0]:
        req_id = data[0][1:]

        if req_id in client.conditions:
            cond = client.conditions[req_id]
            cond['res'] = data[1:]
            cond['cond'].release()
            # cond['cond'].notify_all()
        else:
            print('Returning non existant request')
    else:
        threading.Thread(target = event_thread, args = (client, data)).start()


def clientthread(client):
    try:
        while True:
            #Receiving from client
            data = client.read()
            if data == b'\0': continue
            if not data: break

            event_received(client, data)

    except Exception as e:
        traceback.print_exc(file=sys.stdout)

    print("socket closing")
    client.connected = False
    if client.unique_id:
        del clients[client.unique_id]
    client.socket.close()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

#Bind socket to local host and port
try:
    server_socket.bind(('', 8889))
except Exception as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

server_socket.listen(10)
print('Socket now listening')

class Client:
    def __init__(self, conn, addr):
        self.socket = conn
        self.addr = addr
        self.conditions = {}
        self.connected = False
        self.unique_id = uuid.uuid4().hex;

        self.certificate = None
        self.AUTH = None
        self.CRYP = None
        self.authenticate = False
        self.server_authenticate = True

        #TODO: unique_id must come from a certificate
        # self.unique_id = uuid.uuid4()

    def request(self, msgs):
        msgs = strings_to_bytes(msgs)
        # req_code = random_bytes(16)
        req_code = bytes(uuid.uuid4().hex, 'ascii')
        msgs[0] += b':' + req_code

        # thr_id = threading.get_ident() 
        self.conditions[req_code] = cond = {'res': None, 'cond': threading.Lock()}

        self.send(msgs)
        cond['cond'].acquire()
        while cond['res'] is None:
            cond['cond'].acquire()

        del self.conditions[req_code]

        return cond['res']

    def send(self, msgs):
        msg = b''

        for s in msgs:
            msg += append_arg(s)
        # log('sending: ' + str(msgs))

        msg = struct.pack('>I', len(msgs)) + msg

        if self.CRYP:
            ciphertext = self.CRYP.encrypt(msg)
            Y, iv, ciphertext, salt, tag = self.CRYP.encrypt(msg)
            msg = b''
            msg += append_arg(str(Y.x))
            msg += append_arg(str(Y.y))
            msg += append_arg(iv)
            msg += append_arg(ciphertext)
            msg += append_arg(salt)
            msg += append_arg(tag)

        elif self.server_authenticate:
            sig = g_AUTH.sign(msg)
            msg += append_arg(sig)

        self.socket.sendall(b'S' + msg)

    def read(self):
        msgs = []

        signed = False
        signature = None

        msg = b''

        f = self.socket.makefile('rb')

        START = f.read(1)
        if not START: return None

        if self.CRYP:
            b, YX = read_arg(f)
            b, YY = read_arg(f)
            b, iv = read_arg(f)
            b, ciphertext = read_arg(f)
            b, salt = read_arg(f)
            b, tag = read_arg(f)
            msg = self.CRYP.decrypt(ECPoint(assert_num(YX), assert_num(YY),
                self.CRYP.ec), iv, ciphertext, salt, tag)

            f = io.BytesIO(msg)

        num = f.read(4)
        msg += num

        if not num: return num
        num = struct.unpack('>I', num)[0]

        for i in range(num):
            b, m = read_arg(f)
            msg += b
            msgs.append(m)

        if not self.CRYP and self.authenticate:
            b, signature = read_arg(f)
            if not self.AUTH.verify(msg, signature):
                print('Client failed to verify message')
                return b'\0'

        return msgs

def read_arg(f):
    lb = f.read(4)
    if not lb: return b'', None
    l = struct.unpack('>I', lb)[0]
    m = f.read(l)
    if not m: return b'', None
    return lb + m, bytes(m)

def clientbeat(client):
    while True:
        if client.connected:
            client.send(['t'])
        time.sleep(1)

load_repos()

#now keep talking with the client
while True:
    #wait to accept a connection - blocking call
    conn, addr = server_socket.accept()
    print('Connected with ' + addr[0] + ':' + str(addr[1]))

    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    client = Client(conn, addr)

    threading.Thread(target = clientthread, args = (client,)).start()
    # threading.Thread(target = clientbeat, args = (client,)).start()

server_socket.close()
