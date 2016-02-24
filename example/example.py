#!/usr/bin/env python

from bottle import route
from bottle import run
from bottle import template
from bottle import static_file

from bottle_kerberos import init_kerberos
from bottle_kerberos import requires_authentication

@route('/')
@requires_authentication
@view('index.html')
def index(user):
    return dict(user=user)

@route('/static/<filename:path>')
def static(filename):
    return static_file(filename, root='static')

if __name__ == '__main__':
    init_kerberos(app)
    run(host='0.0.0.0', debug=True)
