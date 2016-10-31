#
# This file is part of BDSA (Big Data Security Analytics)
#
# BDSA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# BDSA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with BDSA.  If not, see <http://www.gnu.org/licenses/>.
#
from paste.translogger import TransLogger
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, Blueprint, send_from_directory, flash, redirect, url_for, Response, request, session
from functools import wraps
from nav import nav
from search import mod_search
from firewall import mod_firewall
from vpn import mod_vpn
from bash import mod_bash
from proxy import mod_proxy
from dashboard import mod_dashboard
from engine import analytics_engine
from forensics import mod_for
from patch_mgmt import mod_pm_dashboard
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import adal
import Cookie
import json
import sys
import os
import random
import string
import base64
import jwt
import logging
import cherrypy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
main = Blueprint('main', __name__)

parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.getcwd()+'/ADAL_PARAMETERS')

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    adal_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')

TEMPLATE_AUTHZ_URL = ('https://login.windows.net/{}/oauth2/authorize?'+
                      'response_type=id_token+code&response_mode=form_post&client_id={}&redirect_uri={}&'+
                      'state={}&nonce={}&resource={}')



#access token is required in session
def access_token_required(func):
    @wraps(func)
    def __decorator():
        if not session.get('id_token'):
            return redirect(url_for('index'))
        return func()

    return __decorator


def validate_id_token(id_token):
    try:
        f = open(adal_parameters['idp_cert'], 'r')
        cert_str = f.read()
        f.close()
    except IOError as e:
        print('Unable to open PEM certificate')
        return False

    cert_obj = load_pem_x509_certificate(cert_str, default_backend())
    public_key = cert_obj.public_key()

    print public_key

    try:
        token = jwt.decode(id_token,
                           public_key,
                           algorithms=['RS256'],
                           audience=adal_parameters['clientId'])
    except Exception as e:
        return False

    return True


def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src='self'"
    if (cherrypy.server.ssl_certificate != None and cherrypy.server.ssl_private_key != None):
        headers['Strict-Transport-Security'] = 'max-age=31536000' # one year


def run_server(app):
    # Enable WSGI access logging via Paste
    app_logged = TransLogger(app)

    # Mount the WSGI callable object (app) on the root directory
    cherrypy.tree.graft(app_logged, '/')
    cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)

    # Set the configuration of the web server
    cherrypy.config.update({
        'engine.autoreload.on': True,
        'log.screen': True,
        'response.stream': True,
        'response.timeout': 3600,
        'server.ssl_module': 'pyOpenSSL',
        'tools.secureheaders.on': True,
        'server.socket_port': 5432,
        'server.socket_host': '0.0.0.0'
    })

    cherrypy.server.ssl_certificate = "domain.crt"
    cherrypy.server.ssl_private_key = "domain.key"
    # Start the CherryPy WSGI web server
    cherrypy.engine.start()
    cherrypy.engine.block()


@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e.message), 404


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e), 500


@main.route('/static/<path:filename>')
def serve_file(filename):
    return send_from_directory('/static', filename)


@main.route('/')
@access_token_required
def index():
    return render_template('index.html')


@main.route('/login')
def login():
        auth_state = (''.join(random.SystemRandom()
                .choice(string.ascii_uppercase + string.digits)
                for _ in range(48)))

        nonce = auth_state
        cookie = Cookie.SimpleCookie()
        cookie['auth_state'] = auth_state
        authorization_url = TEMPLATE_AUTHZ_URL.format(
                adal_parameters['tenant'],
                adal_parameters['clientId'],
                adal_parameters['redirect_uri'],
                auth_state,
                nonce,
                adal_parameters['resource'])

        redirect_to_AAD = redirect(authorization_url)
        response = app.make_response(redirect_to_AAD)
        response.set_cookie('auth_state', auth_state)
        return response


@main.route('/login/callback', methods=['GET','POST'])
def login_callback():
        # Verify AAD id_token
        id_token = request.form['id_token']
        code = request.form['code']

        if id_token:
                if validate_id_token(id_token):
                        session['access_token'] = id_token
                else:
                        return Response(json.dumps({'auth': 'error: invalid token'}), mimetype='application/json')
        else:
                return Response(json.dumps({'auth': 'error: no token found'}), mimetype='application/json')


@main.route('/spark/clearcache')
def clearCache():
    if analytics_engine.clearcache():
        flash('Spark: Cache cleared', 'info')
        return render_template('index.html')
    else:
        flash('Spark: Unable to clear cache', 'error')
        return render_template('index.html')


@main.route('/spark/canceljobs')
def cancelJobs():
    if analytics_engine.canceljobs():
        flash('Spark: Jobs cancelled', 'info')
        return render_template('index.html')
    else:
        flash('Spark: Unable to cancel jobs', 'error')
        return render_template('index.html')


if __name__ == "__main__":
    # Init spark context and load libraries
    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
    #app.config['BOOTSTRAP_CDN_FORCE_SSL'] = False
    app.secret_key = 'super secret key'

    Bootstrap(app)

    # Register Blueprints
    app.register_blueprint(main)
    app.register_blueprint(mod_search)
    app.register_blueprint(mod_firewall)
    app.register_blueprint(mod_vpn)
    app.register_blueprint(mod_bash)
    app.register_blueprint(mod_proxy)
    app.register_blueprint(mod_dashboard)
    app.register_blueprint(mod_for)
    app.register_blueprint(mod_pm_dashboard)

    # Initialize nav bar
    nav.init_app(app)

    # start web server
    run_server(app)
