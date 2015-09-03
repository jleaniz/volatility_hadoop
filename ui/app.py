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
import logging
import cherrypy
from paste.translogger import TransLogger
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, Blueprint, send_from_directory
from nav import nav
from search import mod_search
from firewall import mod_firewall
from vpn import mod_vpn
from bash import mod_bash
from proxy import mod_proxy
from dashboard import mod_dashboard

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

main = Blueprint('main', __name__)


def run_server(app):
    # Enable WSGI access logging via Paste
    app_logged = TransLogger(app)

    # Mount the WSGI callable object (app) on the root directory
    cherrypy.tree.graft(app_logged, '/')

    # Set the configuration of the web server
    cherrypy.config.update({
        'engine.autoreload.on': True,
        'log.screen': True,
        'response.stream': True,
        'response.timeout': 3600,
        # 'server.ssl_module': 'builtin',
        'server.socket_port': 5432,
        'server.socket_host': '0.0.0.0'
    })

    # cherrypy.server.ssl_certificate = "cert.pem"
    # cherrypy.server.ssl_private_key = "privkey.pem"
    # Start the CherryPy WSGI web server
    cherrypy.engine.start()
    cherrypy.engine.block()


@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e.message), 404


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e.message), 500


@main.route('/static/logo.png')
def serve_logo():
    return send_from_directory('/static/logo.png')


@main.route('/')
def index():
    return render_template('index.html')


if __name__ == "__main__":
    # Init spark context and load libraries
    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
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

    # Initialize nav bar
    nav.init_app(app)

    # start web server
    run_server(app)
