#!/usr/bin/python2.7

# Roughly based on this: http://www.piware.de/2011/01/creating-an-https-server-in-python/

gen_cert = ["openssl", "req", "-new", "-x509", "-keyout", "server.pem", "-out", "server.pem", "-days", "365", "-nodes", "-subj", "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd"]

import subprocess
from sys import exit
from os import devnull
import BaseHTTPServer
import SimpleHTTPServer
import ssl

try:
	subprocess.check_output(gen_cert)
except Exception as e:
	print e
	exit(1)

server = BaseHTTPServer.HTTPServer(('127.0.0.1', 4444), 
		SimpleHTTPServer.SimpleHTTPRequestHandler)

server.socket = ssl.wrap_socket(server.socket, 
				certfile='./server.pem', 
				server_side=True)

server.serve_forever()
