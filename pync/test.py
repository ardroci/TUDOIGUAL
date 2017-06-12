#!/usr/bin/python

from client import *

server_connect("127.0.0.1", 8889, None, 'bolis')

server_listen_repo('test:sync_dir_a')
# server_req_key('test')
# server_new_diff("123", "321")
