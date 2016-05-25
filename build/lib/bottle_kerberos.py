import kerberos
import logging

from bottle import request
from bottle import response
from functools import wraps
from socket import gethostname
from os import environ

import time
from hashlib import sha1
from bottle import redirect
from bottle import view
import bottle
from os import urandom
from urllib.parse import urlparse, quote, unquote
import re
from datetime import datetime, timedelta
import pymongo
import pymongo.uri_parser

_DEBUG = True
_SERVICE_NAME = ''
_MAX_CSRF_TIME = 1
_LOGIN_PAGE = 'login'
_LOGOUT_PAGE = 'logout'
_MAX_LOGIN_FAILURES = 0
_PASS_MIN_LEN = 8
_PASS_MAX_LEN = 64
_APP_PREFIX = '/kerberos/'
_REALM = ''
_MONGODB_URI = ''
_LOGINS = ''

# Empty class for ctx
class stack:
    pass


def init_kerberos(app, service = 'HTTP', hostname = gethostname(), mongodb_uri = 'mongodb://localhost:27017/logins/logins', login_page='login', logout_page='logout', max_csrf_time = 300, max_login_failures = 5, pass_min_len = 8, pass_max_len = 64):
    '''
    Configure the GSSAPI service name, and validate the presence of the
    appropriate principal in the kerberos keytab.

    :param app: Bottle App object
    :type app: object
    :param service: GSSAPI service name
    :type service: str
    :param hostname: hostname the service runs under
    :type hostname: str
    :param mongodb_uri: URI for connection to mongodb
    :type mongodb_uri: str
    :param login_page: login page to show
    :type login_page: str
    :param logout_page: logout page to show
    :type logout_page: str
    :param max_csrf_time: Maximum time in seconds the user has to enter login credentials and press submit
    :type max_csrf_time: int
    :param max_login_failures: Maximum number of login failures before user is logged out for an hour
    :type max_login_failures: int
    :param pass_min_len: Minimum number of characters in login name
    :type pass_min_len: int
    :param pass_max_len: Maximum number of characters in login name
    :type pass_max_len: int

    '''
    global _LOGINS, _SERVICE_NAME, _MONGODB_URI, _MAX_CSRF_TIME, _LOGIN_PAGE, _LOGOUT_PAGE, _MAX_LOGIN_FAILURES, _PASS_MIN_LEN, _PASS_MAX_LEN, _REALM
    _SERVICE_NAME = "%s@%s" % (service, hostname)
    _MAX_CSRF_TIME = max_csrf_time
    _LOGIN_PAGE = login_page
    _LOGOUT_PAGE = logout_page
    _MAX_LOGIN_FAILURES = max_login_failures
    _PASS_MIN_LEN = pass_min_len
    _PASS_MAX_LEN = pass_max_len
    _MONGODB_URI = mongodb_uri

    logger=logging.getLogger(__name__)

    # Get mongodb connection
    try:
        _c = _auto_reconnect(pymongo.MongoClient(mongodb_uri))
        parsed_uri = pymongo.uri_parser.parse_uri(mongodb_uri)
        mongo_db = parsed_uri.get('database') or 'logins'
        _db = _c[mongo_db]
        mongo_collection = parsed_uri.get('collection') or 'logins'
        _LOGINS = _db[mongo_collection]
    except pymongo.errors.PyMongoError as e:
        logger.error('Error: %s - connecting to database %s!' % (e, mongodb_uri), exc_info = 1)

    if 'KRB5_KTNAME' not in environ:
        logger.warn("Kerberos: set KRB5_KTNAME to your keytab file")
    else:
        try:
            principal = kerberos.getServerPrincipalDetails(service, hostname)
        except kerberos.KrbError as exc:
            logger.warn("Kerberos: %s" % exc)
        else:
            logger.info("Kerberos: server is %s" % principal)
            _REALM = principal.split('@')[1]

    app.mount(_APP_PREFIX, login_app)


def _unauthorized(error=''):
    '''
    Indicate that authentication is required
    '''
    response.set_header('WWW-Authenticate', 'Negotiate')
    response.status = 401
    request.session['return_to'] = quote(request.url)
    return _show_login_form(error)


def _forbidden():
    '''
    Indicate a complete authentication failure
    '''
    response.status = 403
    return ''


def _gssapi_authenticate(token):
    '''
    Performs GSSAPI Negotiate Authentication

    On success also stashes the server response token for mutual authentication
    at the top of request context with the name kerberos_token, along with the
    authenticated user principal with the name kerberos_user.

    @param token: GSSAPI Authentication Token
    @type token: str
    @returns gssapi return code or None on failure
    @rtype: int or None
    '''
    state = None
    # Should be a request local object
    ctx = request.ctx
    try:
        rc, state = kerberos.authGSSServerInit(_SERVICE_NAME)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            return None
        rc = kerberos.authGSSServerStep(state, token)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            ctx.kerberos_token = kerberos.authGSSServerResponse(state)
            ctx.kerberos_user = kerberos.authGSSServerUserName(state)
            return rc
        elif rc == kerberos.AUTH_GSS_CONTINUE:
            return kerberos.AUTH_GSS_CONTINUE
        else:
            return None
    except kerberos.GSSError:
        return None
    finally:
        if state:
            kerberos.authGSSServerClean(state)


def requires_authentication(function):
    '''
    Require that the wrapped view function only be called by users
    authenticated with Kerberos. The view function will have the authenticated
    users principal passed to it as its first argument.

    :param function: bottle view function
    :type function: function
    :returns: decorated function
    :rtype: function
    '''
    logger=logging.getLogger(__name__)

    @wraps(function)
    def decorated(*args, **kwargs):
        session = request.session
        # If session already contains usenname - use it
        if session.has_key('user'):
            # Check session ip against client, kill session if not
            # if not session['ip']==request.remote_route[0]:
            if not session['ip'] == request.remote_route[0]:
                session.invalidate()
                # abort(400,'<meta http-equiv="refresh" content="5; url=https://ssh.ku.dk/">Your session is valid for this client IP Address!')
                return _unauthorized(error = 'Your session is invalid for this client IP Address!')

            if _DEBUG:
                logger.debug("Remember: %s" % session['remember'])
                logger.debug("accessed: %s " % session.last_accessed)
                logger.debug("timeout: %s" % session.timeout)
                logger.debug("time: %s" % time.time())
            # Check if remember is on, and use little session timer
            if not session['remember']:
                # If time has passed:
                # session access time + session.timeout
                # Then delete session and login again
                if session.last_accessed + session.timeout < time.time():
                    session.delete()
                    return _unauthorized()
            else:
                # If time has passed:
                # session access time + session.remember
                # Then delete session and login again
                if session.last_accessed + session['remember'] < time.time():
                    session.delete()
                    return _unauthorized(error = 'Your session expired!')
            return function(request.session.get('user'), *args, **kwargs)

        header = request.headers.get("Authorization")
        if header:
            ctx = request.ctx = stack()
            token = ''.join(header.split()[1:])
            logger.debug('Token: %s' % token)
            rc = _gssapi_authenticate(token)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                # Set session user
                request.session['user'] = ctx.kerberos_user
                output = function(ctx.kerberos_user, *args, **kwargs)
                if ctx.kerberos_token is not None:
                    response.set_header('WWW-Authenticate',' '.join(['negotiate',
                                                                     ctx.kerberos_token]) )
                return output
            elif rc != kerberos.AUTH_GSS_CONTINUE:
                return _forbidden()
        return _unauthorized()
    return decorated


# CRSF functions
def _gen_csrf():
    return sha1(urandom(12)).hexdigest()


def _set_csrf(request):
    request.session['csrf_token'] = _gen_csrf()
    request.session['csrf_time'] = time.time()


def _check_csrf(request):
    logger = logging.getLogger(__name__)
    logger.debug('csrf_token: %s = %s' % (request.session.get ('csrf_token'), request.POST['ct']))
    logger.debug('csrf_time : %i + %i = %i' % (request.session.get ('csrf_time', 0), _MAX_CSRF_TIME, time.time ()))
    try:
        if request.POST['ct'] == request.session['csrf_token'] and time.time() < request.session['csrf_time'] + _MAX_CSRF_TIME:
            del (request.session['csrf_token'], request.session['csrf_time'])
            return True
    except KeyError as e:
        logger.debug('check_csrf error: %s' % e)
    # Only delete session variables if they exists, otherwise keyerror
    for v in ['csrf_token', 'csrf_time']:
        if v in request.session:
            del (request.session[v])
    return False


# Input validating functions
from string import ascii_letters, digits, punctuation
VALID_ACCENTED = 'áÁàÀâÂäÄãÃåÅæÆçÇéÉèÈêÊëËíÍìÌîÎïÏñÑóÓòÒôÔöÖõÕøØœŒßúÚùÙûÛüÜ'
VALID_PATH_CHARACTERS = ascii_letters + digits + '/.,_-+='\
     + ' :;+@%' + VALID_ACCENTED
VALID_TEXT_CHARACTERS = VALID_PATH_CHARACTERS + '?!#$£€%&()[]{}*'\
     + '"' + "'`|^~" + '\\' + '\n\r\t'
VALID_FQDN_CHARACTERS = ascii_letters + digits + '.-'
VALID_BASEURL_CHARACTERS = VALID_FQDN_CHARACTERS + ':/_'
VALID_URL_CHARACTERS = VALID_BASEURL_CHARACTERS + '?;&%='

name_extras = VALID_ACCENTED + ' -@.'
integer_extras = '+-'
password_extras = '£€'

VALID_INTEGER_CHARACTERS = digits + integer_extras
VALID_PASSWORD_CHARACTERS = VALID_TEXT_CHARACTERS + punctuation + password_extras
VALID_NAME_CHARACTERS = ascii_letters + digits + name_extras

VALID_QUERY_CONTENT = VALID_TEXT_CHARACTERS


def _auto_reconnect(call):
    ''' Function to automatically reconnect if theres a
    mongo auto-reconnect error'''
    logme = logging.getLogger(__name__)
    for i in range(6):
        try:
            return call
        except pymongo.errors.AutoReconnect:
            logme.warning('Reconnect to mongodb')
            time.sleep(pow(2, i))
    logme.error('Cannot reconnect to mongodb')


def _valid_qv(qv):
    '''Check if query variable exists and if data is within allowed characters, else return None'''
    logr = logging.getLogger(__name__)
    if qv in request.params:
        data = request.params[qv]
        # Check if all chars in data is within VALID_QUERY_CONTENT
        for c in data:
            # If they are not in list of valid chars, return empty string
            if c not in VALID_QUERY_CONTENT:
                logr.warning ("validating query content failed on %s in %s" % (c,data))
                print ("validating query content failed on %s in %s" % (c,data))
                return ''
        return data
    else:
        return None


def _valid_route(url):
    '''Check if url is a valid app route, else return None'''
    valid_url = ''.join(urlparse(url)[2:]).rstrip('/')
    try:
        request.app.get_url(valid_url)
        return valid_url
    except bottle.RouteBuildError:
        return False


def _valid_user(user):
    '''Check if user is with limits of allowed characters, else return None'''
    user = user.strip()
    # Pure KU userid is ok
    if re.match(r'^\w{3}\d{3}$',user):
        return user
    # Email address is ok
    elif re.match(r'^[\w.-]+@\w+\.[\w.]+$',user):
        return user
    else:
        return None


def _valid_pass(pw):
    '''Check if pw and correct length and is with limits of allowed characters, else return None'''
    logger = logging.getLogger(__name__)
    if not _PASS_MIN_LEN <= len(pw) <= _PASS_MAX_LEN:
        return None
    # Must not iterate over binary string
    for c in pw.decode('utf8'):
        # If they are not in list of valid chars, return None
        if c not in VALID_PASSWORD_CHARACTERS.decode('utf8'):
            # Must log in binary string
            logger.debug ("Invalid password character: %s in password: %s", c.encode('utf8'), pw)
            logger.debug ("Valid_password_characters: %s", VALID_PASSWORD_CHARACTERS)
            return None
    return pw

def _login(user, pwd, remember):
    '''Try to login user with kerberos'''
    try:
        kerberos.checkPassword(user, pwd, _SERVICE_NAME, _REALM)
    except kerberos.BasicAuthError:
        return False

login_app = bottle.app()


@login_app.get('/login')
@login_app.post('/login')
@view(_LOGIN_PAGE)
def login():
    '''Login a user.
    Create session object and optionally redirect to earlier url'''
    logger = logging.getLogger(__name__)
    if 'user' in request.POST:
        user = _valid_user(request.POST.get('user', ''))
        if user is None:
            return _show_login_form(error = "ERR-05: Invalid username")
        pwd = _valid_pass(request.POST.get('pwd', ''))
        if pwd is None:
            logger.error ('ERR-06: Invalid password for user: %s', user)
            logger.debug ("ERR-06: Invalid password: %s", request.POST.get('pwd', ''))
            return _show_login_form(error = "ERR-06: Invalid password")
        # Check if csrf token matches, or fail
        if not _check_csrf(request):
            return _show_login_form(error = "ERR-07: Session invalid, may have expired")
        # Check if user and pwd were validated or fail
        remember = request.POST.get('remember-me', '') == 'remember-me'
        # Where does he come from
        remote_ip = request.remote_route[0]
        # Look up failed tries in database and fail if over max_failures
        d = datetime.now() - timedelta(hours=1)
        failures = _auto_reconnect(_LOGINS.find({'when': {"$gt": d}, 'user': user, 'what': 'failure'}).count())
        if failures is None:
            # We could not connect and verify, so do not login
            logger.error('Error: Cannot connect to db, cannot verify %s' % user, exc_info = 1)
            return _show_login_form(error="ERR-08: Authentication failed")
        if failures > _MAX_LOGIN_FAILURES:
            # 5 failures per hour is the max
            logger.warning('user %s has failed more than %i times within 1 hour - denied' % (user, _MAX_LOGIN_FAILURES))
            return _show_login_form(error="ERR-08: Authentication failed")
        if _login(user, pwd):
            # Userid = id URL with KU userid only as key
            session = request.session
            session['user'] = user
            session['ip'] = remote_ip
            session['remember'] = remember
            session.save()
            post = {'user': user,
                    'ip': remote_ip,
                    'when': datetime.now(),
                    'what': 'success',
            }
            _auto_reconnect(_LOGINS.insert(post))
            session.save()
            logger.info ("INFO-01: User %s logged in successfully", user)
            success_to = _valid_route(request.query.success_to)
            if success_to:
                redirect(unquote(success_to))
            else:
                redirect('/')
        else:
            logger.error("ERR-08: Authentication failed for user %s", user)
            return _show_login_form(error = "ERR-08: Authentication failed")
    return _show_login_form()


# DO NOT CACHE headers
dont_cache_headers =  { 'Cache-Control' : 'no-cache, no-store, must-revalidate',
                        'Pragma' : 'no-cache',
                        'Expires' : '0' }


def _show_login_form(error = ''):
    '''Present login form to user.
    Optionally add query to redirect user to former url'''
    _set_csrf(request)
    # Add dont_cache_headers to response headers to avoid unintentional caching
    response.headers.update (dont_cache_headers)
    return dict(session=request.session,
                csrf_token = request.session['csrf_token'],
                default_user = request.session.get('user'),
                success_to = _valid_route(request.query.success_to),
                error = error)


@login_app.route('/logout')
@view(_LOGOUT_PAGE)
def logout():
    '''
    Logout a user.
    Delete session object and optionally redirect to return_to
    '''
    return_to = _valid_qv('return_to')
    request.session.delete()
    if return_to:
        redirect(return_to)
    else:
        return ''
