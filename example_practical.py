



################################################
#                                              #
# WARNING: Intentionally vulnerable code below #
#                                              #
################################################




import commands
import hashlib
import os
import pickle
import pipes
import posix
import taint
import urllib
import urlparse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

SECRET_KEY = 'l33t_passwd'


class HtmlMerit(Merit):
  propagation = Merit.FullPropagation

class SecretMerit(Merit):
  propagation = Merit.NonePropagation

class ShellMerit(Merit):
  propagation = Merit.FullPropagation

class PickleMerit(Merit):
  propagation = Merit.NonePropagation

class Handler(BaseHTTPRequestHandler):
  def get_parameters(self):
    return urlparse.parse_qs("".join(self.path.split('?')[1:]))

  def send_response(self, data):
    self.wfile.write(data)

  def do_GET(self):
    self.send_response(200)
    self.send_header("Content-type", "text/plain")
    self.end_headers()

    if not '?' in self.path:
      self.send_response("Hello!")
      self.wfile.close()
      return

    params = self.get_parameters()
    path = self.path.split('?')[0]

    # Example 1 -- Secret Leak
    # By leaking the hash of the secret the attack can bruteforce the SECRET_KEY
    # offline.
    #
    # Exercise attack request:
    # /hashleak?
    if path == '/hashleak':
      self.send_response("your instance ID (= hash of your key) is: %s" % \
          (hashlib.md5(SECRET_KEY).hexdigest()))

    # Example 2 -- Unsafe Pickle
    # It is not safe to unpickle untrusted strings, as classes can define
    # routines that declare how they should be unpickled. This can lead to
    # remote code execution vulnerablities.
    #
    # Exercise attack request:
    # /pickle?value=
    # "cposix\nsystem\np0\n(S'id>/tmp/test'\np1\ntp2\nRp3\n."
    elif path == '/pickle':
      user_value = urllib.unquote(params['value'][0])  # TODO fix
      data = pickle.loads(user_value)
      self.send_response("unpickled data: %r" % (data))

    # Example 3 -- Command Injection
    # It is not safe to contatenate strings for use in a shell command without
    # sanitizing the user-supplied strings first.
    #
    # Exercise attack request:
    # google.org;echo foo>/tmp/foo'
    elif path == '/cmd':
      data = commands.getoutput('whois %s' % params['value'][0])
      self.send_response("whois data: %r" % (data))

    # Example 4 -- Reflected XSS
    # It is safe to reflect user-supplied strings in a HTTP response without
    # sanitizing them first.
    #
    # Exercise attack request:
    # /reflect?value= <img src=x onerror=alert(0);>
    elif path == '/reflect':
      data = params['value'][0]
      data = data.upper()
      self.send_response("reflected data: %s" % (data))

    # Example 5 -- Stored XSS
    # It is safe to reflect user-supplied strings in a HTTP response without
    # sanitizing them first.
    #
    # Exercise attack request:
    # TODO
    elif path == '/store':
      fh = open('/tmp/db','w')
      fh.write(params['value'][0])
      fh.close()

      self.send_response("stored")
    elif path == '/get':
      fh = open('/tmp/db','r')
      data = fh.read()
      data = data.taint()
      fh.close()

      self.send_response("stored: %s" % (data))

    # Example 6 -- Arbritary File Read
    # TODO
    # Example 7 -- Arbritary File Write
    # TODO
    self.wfile.close()

taint.enable('example_practical.json')
SECRET_KEY = SECRET_KEY.taint()  # Manually taint this string

try:
  server = HTTPServer(('localhost', 8888), Handler)
  print('Started http server')
  server.serve_forever()
except KeyboardInterrupt:
  print('^C received, shutting down server')
  server.socket.close()
