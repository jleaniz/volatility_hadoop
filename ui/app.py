from flask import (
    Flask, request, render_template, flash, redirect, url_for, Response, Blueprint, make_response, abort
)

from flask_bootstrap import (
    __version__ as FLASK_BOOTSTRAP_VERSION, Bootstrap
)

from flask_nav.elements import (
    Navbar, View, Subgroup, Link, Text, Separator
)

from flask_nav import Nav
from flask_wtf import Form
from wtforms.fields import StringField, SubmitField, SelectField
from wtforms.fields.html5 import DateField
from wtforms.validators import DataRequired, Email
import gzip


class UserForm(Form):
    name = StringField(u'VPN Username', validators=[Email(message="Invalid input. Ex: srm-ais@email.com")])
    submit = SubmitField(u'Lookup')


class UserDateForm(Form):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    name = StringField(u'Username', validators=[DataRequired(message="Invalid input. Ex: jdoe")])
    submit = SubmitField(u'Lookup')


class DateForm(Form):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    submit = SubmitField(u'Lookup')


class SearchForm(Form):
    table = SelectField(choices=[('proxysg', 'proxysg'), ('firewall', 'firewall'), ('ciscovpn', 'ciscovpn')],
                        validators=[DataRequired(message='Required field')]
                        )
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    query = StringField(u'Query', validators=[DataRequired(message="Field required")])
    num = SelectField(
        choices=[('10', '10'), ('100', '100'), ('1000', '1000'), ('10000', '10000'), ('100000', '100000')],
        validators=[DataRequired(message='Required field')]
    )
    lookup = SubmitField(u'Lookup')
    download = SubmitField(u'Download')


main = Blueprint('main', __name__)
nav = Nav()

# We're adding a navbar as well through flask-navbar. In our example, the
# navbar has an usual amount of Link-Elements, more commonly you will have a
# lot more View instances.
nav.register_element('frontend_top', Navbar(
    View('BDSA', '.index'),
    View('Dashboard', '.index'),
    Subgroup(
    'Analytics',
    Text('VPN'),
    Separator(),
    Link('User stats', '/vpn/user'),
    Separator(),
    Text('Proxy'),
    Separator(),
    Link('Malware by user', '/proxy/malware/user'),
    Link('Top 10 Transfers', '/proxy/top/transfers'),
    Separator(),
    Text('Bash'),
    Separator(),
    Link('Keyword search', '/bash/keyword'),
    ),
    Subgroup(
        'Forensics',
        Link('Timeline analysis', '/search'),
    ),
    Subgroup(
        'Search',
        Link('Custom query', '/search'),
    ),

))

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from engine import AnalyticsEngine


@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e.message)


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e.message)


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
        logging.info(json)
        return render_template('vpnGC.html', json=json)
    else:
        return 'Username unspecified.'


@main.route('/proxy/LoginsByUser/google/<username>/<fromdate>/<todate>')
def proxyGoogleFormat(username, fromdate, todate):
    if username and fromdate and todate:
        json = analytics_engine.getProxyUserMalwareHits(username, fromdate, todate)
        logging.info(json)
        return render_template('proxyGC.html', json=json)
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


@main.route('/search/<table>/<fromdate>/<todate>/<query>/<num>')
def search(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)

    def generate():
        yield '{"%s": [\n' % (table)
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')

@main.route('/api/bash/keyword/<keyword>')
def bashKeyword(keyword):
    if keyword:
        #json = analytics_engine.bashKeywordSearch(keyword)
        #logging.info(json)
        return Response(analytics_engine.bashKeywordSearch(keyword), mimetype='application/json')
    else:
        return 'Keyword or date unspecified.'

@main.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.bashKeyword', keyword=form.name.data ))
    return render_template("proxy.html", form=form)

def buildJSON(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)
    results = []

    results.append('{"%s": [\n' % (table))
    for item in jsonResult:
        results.append(item + ',\n')

    results.append('{}\n]}')

    return results


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


@main.route("/vpn/user", methods=('GET', 'POST'))
def vpn_user():
    form = UserForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.vpnGoogleFormat', username=form.name.data))
    return render_template("vpn.html", form=form)


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


@main.route("/search", methods=('GET', 'POST'))
def search_view():
    Lookupform = SearchForm(csrf_enabled=False)

    if Lookupform.validate_on_submit() and Lookupform.lookup.data:
        return redirect(
            url_for('main.search', table=Lookupform.table.data, fromdate=Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                    todate=Lookupform.todate.data.strftime('%Y-%m-%d'), query=Lookupform.query.data,
                    num=Lookupform.num.data))
    if Lookupform.validate_on_submit() and Lookupform.download.data:
        data = buildJSON(Lookupform.table.data, Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                         Lookupform.todate.data.strftime('%Y-%m-%d'),
                         Lookupform.query.data, Lookupform.num.data)
        response = download(data)
        return response

    return render_template("search.html", form=Lookupform)


@main.route('/')
def index():
    return render_template('index.html')


def create_app(spark_context):
    global analytics_engine

    analytics_engine = AnalyticsEngine(spark_context)

    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.secret_key = 'super secret key'

    Bootstrap(app)

    app.register_blueprint(main)

    nav.init_app(app)
    return app
