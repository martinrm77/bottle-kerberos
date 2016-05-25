Bottle-Kerberos
==============

Bottle-Kerberos is an extension to `PyBottle`_ that allows you to trivially add
`Kerberos`_ based authentication to your website. It depends on both PyBottle and
`python-kerberos`_ 1.1.1+. You can install the requirements from PyPI with
`easy_install` or `pip` or download them by hand.

Unfortunately, as is the case with most things kerberos, it requires a kerberos
environment as well as a keytab. Setting that up is outside the scope of this
document.

The official copy of this documentation is available at `Read the Docs`_.

Installation
------------

Install the extension with one of the following commands::

    $ easy_install Bottle-Kerberos

or alternatively if you have `pip` installed::

    $ pip install Bottle-Kerberos

How to Use
----------

To integrate Bottle-Kerberos into your application you'll need to generate your
keytab set the environment variable `KRB5_KTNAME` in your shell to the location
of the keytab file.
You must initialize Bottle_Kerberos with your values to support the login form.
It has some sane defaults, but can be customized to fit your local policy. The only
mandatory option is the bottle app instance, that you wish to use. Bottle_Kerberos
the installs the encessary login form methods on this application. It will automatically
try to connect to an mongodb instance for enforcing maximum logins with a timeframe of
one hour::

    from bottle_kerberos import init_kerberos

    init_kerberos(app, service = 'HTTP', hostname = gethostname(), mongodb_uri = 'mongodb://localhost:27017/logins/logins', login_page='login', logout_page='logout', max_csrf_time = 300, max_login_failures = 5, pass_min_len = 8, pass_max_len = 64)

After that, it should be as easy as decorating any view functions you wish to
require authentication, and changing them to accept the authenticated user
principal as their first argument::

    from bottle_kerberos import requires_authentication

    @route("/protected")
    @requires_authentication
    def protected_view(user):
        ...




How it works
------------

When a protected view is accessed by a client, it will check to see if the
request includes authentication credentials in an `Authorization` header. If
there are no such credentials, the application will respond immediately with a
`401 Unauthorized` response with login form which includes a `WWW-Authenticate` header field
with a value of `Negotiate` indicating to the client that they are currently
unauthorized, but that they can authenticate using Negotiate authentication.

If credentials are presented in the `Authorization` header, the credentials will
be validated, the principal of the authenticating user will be extracted, and
the protected view will be called with the extracted principal passed in as the
first argument.
If username and password is sent with the login form, the server with authenticate with
 kerberos and your session is now authenticated.

Once the protected view returns, a `WWW-Authenticate` header will be added to
the response which can then be used by the client to authenticate the server.
This is known as mutual authentication.

Full Example
------------

To see a simple example, you can download the code `from github
<http://github.com/martinrm77/bottle-kerberos>`_. It is in the example directory.

Changes
-------
1.1.0
`````

-     Totally redone to include login form in the 401 Unauthorized response if client doesnt have a kerberos ticket

1.0.2
`````

-     Works completely now, with kerberos

1.0.1
`````

-     bug fixes

1.0.0
`````

-     initial implementation - forked and adapted to bottle from flask-kerberos by Michael Komitee

