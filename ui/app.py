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
import cherrypy
from paste.translogger import TransLogger
from pyspark import SparkContext, SparkConf
from config import config as conf

import gzip
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from flask_bootstrap import Bootstrap
from flask import (
    Flask, render_template, Blueprint, redirect, url_for, Response, make_response
)
from forms import DateForm, UserDateForm, SearchForm, CustomSearchForm, UserForm
from nav import nav
from engine import AnalyticsEngine


main = Blueprint('main', __name__)


def init_spark_context():
    # load spark context
    appConfig = conf.Config()
    # IMPORTANT: pass aditional Python modules to each worker
    sc = SparkContext(conf=appConfig.setSparkConf())

    return sc


sc = init_spark_context()
analytics_engine = AnalyticsEngine(sc)


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
    return render_template('404.html', error=e.message)


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e.message)


@main.route('/')
def index():
    return render_template('index.html')


def buildJSON(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)
    results = []

    results.append('{"%s": [\n' % (table))
    for item in jsonResult:
        results.append(item + ',\n')

    results.append('{}\n]}')

    return results


def buildJSONCustom(query):
    jsonResult = analytics_engine.getCustomSearchResults(query)
    results = []

    results.append('{"%s": [\n' % ("search"))
    for item in jsonResult:
        results.append(item + ',\n')

    results.append('{}\n]}')

    return results


@main.route('/proxy/LoginsByUser/google/<username>/<fromdate>/<todate>')
def proxyGoogleFormat(username, fromdate, todate):
    if username and fromdate and todate:
        json = analytics_engine.getProxyUserMalwareHits(username, fromdate, todate)
        logging.info(json)
        return render_template('display_table.html', json=json)
    else:
        return 'Username or date unspecified.'


@main.route('/proxy/topTransfers/google/<fromdate>/<todate>')
def getProxyTopTransfers(fromdate, todate):
    if fromdate and todate:
        (jsonTable, jsonChart) = analytics_engine.getTopTransfersProxy(fromdate, todate)
        # logging.info(jsonTable, jsonChart)
        return render_template('proxyTopTransfers.html', jsonTable=jsonTable, jsonChart=jsonChart)
    else:
        return 'Date unspecified.'


@main.route("/proxy/malware/user", methods=('GET', 'POST'))
def proxy_user():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.proxyGoogleFormat', username=form.name.data, fromdate=form.fromdate.data.strftime('%Y-%m-%d'),
                    todate=form.todate.data.strftime('%Y-%m-%d')))
    return render_template("proxy.html", form=form)


@main.route("/proxy/top/transfers", methods=('GET', 'POST'))
def proxyTopTransfers():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.getProxyTopTransfers', fromdate=form.fromdate.data.strftime('%Y-%m-%d'),
                                todate=form.todate.data.strftime('%Y-%m-%d')))
    return render_template("proxy.html", form=form)


@main.route('/api/bash/keyword/<keyword>')
def bashKeyword(keyword):
    if keyword:
        json = analytics_engine.bashKeywordSearch(keyword)
        logger.info(json)
        return render_template('display_table.html', json=json.decode('utf-8'))
    else:
        return 'Keyword or date unspecified.'


@main.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.bashKeyword', keyword=form.name.data))
    return render_template("proxy.html", form=form)


@main.route("/api/vpn/byUser/<username>")
def vpnJSON(username):
    if username:
        rdd = analytics_engine.getVPNLoginsByUserJSON(username)

        def generate():
            yield '{"%s": [\n' % (username)
            for doc in rdd.collect():
                yield doc + ',\n'
            yield "{}\n]}"

        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'


@main.route("/api/vpn/identifyUser/<date>/<remoteip>")
def identifyVPNAPI(date, remoteip):
    if date and remoteip:
        rdd = analytics_engine.identifyVPNUser(remoteip, date)

        def generate():
            yield '{"%s": [\n' % (remoteip)
            for doc in rdd.collect():
                yield doc + ',\n'
            yield "{}\n]}"

        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'


@main.route('/vpn/LoginsByUser/google/<username>')
def vpnGoogleFormat(username):
    if username:
        json = analytics_engine.getVPNLoginsByUserGoogle(username)
        logger.info(json)
        return render_template('vpnGC.html', json=json)
    else:
        return 'Username unspecified.'


@main.route("/vpn/user", methods=('GET', 'POST'))
def vpn_user():
    form = UserForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.vpnGoogleFormat', username=form.name.data))
    return render_template("vpn.html", form=form)


@main.route('/download/<file>')
def download(content):
    f = gzip.open('/tmp/results.gz', 'wb')
    try:
        for line in content:
            f.write(line)
    finally:
        f.close()

    r = open('/tmp/results.gz', 'rb')
    try:
        buf = r.read()
    finally:
        r.close()

    response = make_response(buf)
    # This is the key: Set the right header for the response
    # to be downloaded, instead of just printed on the browser
    response.headers["Content-Disposition"] = "attachment; filename=results.gz"
    return response


@main.route('/search/<table>/<fromdate>/<todate>/<query>/<num>')
def search(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)

    def generate():
        yield '{"%s": [\n' % (table)
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')


@main.route('/search/custom/<query>')
def CustomSearch(query):
    jsonResult = analytics_engine.getCustomSearchResults(query)

    def generate():
        yield '{"%s": [\n' % ('search')
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')


@main.route("/search", methods=('GET', 'POST'))
def search_view():
    Lookupform = SearchForm(csrf_enabled=False)

    if Lookupform.validate_on_submit() and Lookupform.lookup.data:
        return redirect(
            url_for('main.search', table=Lookupform.table.data, tables=Lookupform.tables,
                    fromdate=Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                    todate=Lookupform.todate.data.strftime('%Y-%m-%d'), query=Lookupform.query.data,
                    num=Lookupform.num.data))

    if Lookupform.validate_on_submit() and Lookupform.download.data:
        data = buildJSON(Lookupform.table.data, Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                         Lookupform.todate.data.strftime('%Y-%m-%d'),
                         Lookupform.query.data, Lookupform.num.data)
        response = download(data)
        return response

    return render_template("search.html", form=Lookupform)


@main.route("/search/custom", methods=('GET', 'POST'))
def custom_search_view():
    Search = CustomSearchForm(csrf_enabled=False)

    if Search.validate_on_submit() and Search.lookup.data:
        return redirect(url_for('main.CustomSearch', query=Search.query.data))

    if Search.validate_on_submit() and Search.download.data:
        data = CustomSearch(Search.query.data)
        response = download(data)
        return response

    return render_template("custom_search.html", form=Search)


if __name__ == "__main__":
    # Init spark context and load libraries
    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.secret_key = 'super secret key'

    Bootstrap(app)

    app.register_blueprint(main)

    nav.init_app(app)
    # start web server
    run_server(app)
