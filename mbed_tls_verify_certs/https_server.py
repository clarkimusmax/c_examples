#!/usr/bin/python2.7

# Roughly based on this: http://www.piware.de/2011/01/creating-an-https-server-in-python/

import BaseHTTPServer
import SimpleHTTPServer
import ssl
from pprint import pprint

server = BaseHTTPServer.HTTPServer(('127.0.0.1', 4444), 
		SimpleHTTPServer.SimpleHTTPRequestHandler)

ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile="certs/CA.pem")
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = False
#ctx.load_verify_locations(cafile="certs/CA.pem")
ctx.load_cert_chain("certs/Server.pem", keyfile="certs/Server.key")
server.socket = ctx.wrap_socket(server.socket, server_side=True)

pprint(ctx.get_ca_certs())

try:
	server.serve_forever()
except KeyboardInterrupt:
	pass
