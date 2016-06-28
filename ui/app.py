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
from flask import Flask, render_template, Blueprint, send_from_directory, flash, redirect, url_for
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

main = Blueprint('main', __name__)


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
    return render_template('500.html', error=e.message), 500


@main.route('/static/<path:filename>')
def serve_file(filename):
    return send_from_directory('/static', filename)


@main.route('/')
def index():
    return render_template('index.html')


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
