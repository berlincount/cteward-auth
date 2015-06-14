# coding: utf-8

from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import render_template, redirect, jsonify
from flask_ldapconn import LDAPConn
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from flask_oauthlib.provider import OAuth2Provider
from pprint import pprint
import json
import ssl
import os

# basic configuration
config = {
    'name':  'cteward-auth',
    'debug': False,
    'appconfig':   {
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
    },
    'app': {
        'host': '0.0.0.0'
    }
}

if 'CTEWARD_AUTH_CONFIG' in os.environ:
    configfile = os.environ['CTEWARD_AUTH_CONFIG']
else:
    configfile = '/etc/cteward/auth.json'

with open(configfile) as json_file:
    config.update(json.load(json_file))

# additional configuration
if 'ssl' in config:
    if not 'PREFERRED_URL_SCHEME' in config['appconfig']:
        config['appconfig']['PREFERRED_URL_SCHEME'] = 'https'
    if not 'ciphers' in config['ssl']:
        config['ssl']['ciphers'] = 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH'
    if not 'dh_params' in config['ssl']:
        config['ssl']['dh_params'] = '/etc/cteward/dhparams.pem'

app = Flask(config['name'], template_folder='templates')
app.debug = config['debug']
app.secret_key = config['secret']
app.config.update(config['appconfig'])

if 'ldapconfig' in config:
    app.config.update(config['ldapconfig'])
    if not 'LDAP_VERIFY_SSL' in config['ldapconfig'] or config['ldapconfig']['LDAP_VERIFY_SSL']:
        app.config.update({'LDAP_REQUIRE_CERT': ssl.CERT_REQUIRED})
    ldap = LDAPConn(app)

db = SQLAlchemy(app)
oauth = OAuth2Provider(app)

if 'ssl' in config:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(config['ssl']['certfile'],config['ssl']['keyfile'])
    ssl_context.set_ciphers(config['ssl']['ciphers'])
    ssl_context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ssl_context.load_dh_params(config['ssl']['dh_params'])
    # FIXME: missing OCSP stapling
    # FIXME: disable SSL session tickets
else:
    ssl_context = None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)


class Client(db.Model):
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


#### TODO: integrated this properly
username = 'username'
password = 'password'
attribute = 'uid'
basedn = 'ou=crew,dc=c-base,dc=org'
search_filter = ('(memberOf=cn=crew,ou=groups,dc=c-base,dc=org)')

with app.app_context():
    retval = ldap.authenticate(username, password, attribute, basedn, search_filter)
    if retval:
        print('Welcome %s.' % username)
    else:
        print('Auth failed.')
####

@app.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)


@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_id=gen_salt(40),
        client_secret=gen_salt(50),
        _redirect_uris=' '.join([
            'http://localhost:8000/authorized',
            'http://127.0.0.1:8000/authorized',
            'http://127.0.1:8000/authorized',
            'http://127.1:8000/authorized',
            ]),
        _default_scopes='email',
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
    )


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)

def add_common_response_headers(response):
    # security headers
    response.headers.add('Strict-Transport-Security','max-age=63072000; includeSubdomains; preload')
    response.headers.add('X-Frame-Options','DENY')
    response.headers.add('X-Content-Type-Options','nosniff')
    return response

if __name__ == '__main__':
    db.create_all()
    app.after_request(add_common_response_headers)
    app.run(ssl_context=ssl_context, **config['app'])
