from flask import (
    Flask, request, render_template, flash, redirect, url_for, Response, Blueprint
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


class UserForm(Form):
    name = StringField(u'VPN Username', validators=[Email(message="Invalid input. Ex: srm-ais@ubisoft.com")])
    submit = SubmitField(u'Lookup')


class UserDateForm(Form):
    date = DateField(u'Date', format='%Y-%m-%d', validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    name = StringField(u'Username', validators=[DataRequired(message="Invalid input. Ex: jdoe")])
    submit = SubmitField(u'Lookup')


class DateForm(Form):
    date = DateField(u'Date', format='%Y-%m-%d', validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    submit = SubmitField(u'Lookup')


class SearchForm(Form):
    table = SelectField(choices=[('proxysg', 'Proxy'), ('firewall', 'Firewall'), ('ciscovpn', 'VPN')],
                        validators=[DataRequired(message='Required field')]
                        )
    sdate = DateField(u'Start Date', format='%Y-%m-%d',
                      validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    edate = DateField(u'End Date', format='%Y-%m-%d',
                      validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    query = StringField(u'Query', validators=[DataRequired(message="Field required")])
    submit = SubmitField(u'Lookup')


main = Blueprint('main', __name__)
nav = Nav()

# We're adding a navbar as well through flask-navbar. In our example, the
# navbar has an usual amount of Link-Elements, more commonly you will have a
# lot more View instances.
nav.register_element('frontend_top', Navbar(
    View('BDSA', '.index'),
    View('Home', '.index'),
    View('Dashboard', '.index'),
    Subgroup(
        'Search',
        Link('Custom query', '/search'),
    ),
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
    ),
))

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from engine import AnalyticsEngine

'''
@main.route("/api/vpn/byUser/<username>")
def vpnJSON(username):
    if username:
        rdd = analytics_engine.getVPNLoginsByUserJSON(username)
        def generate():
            yield '{"%s": [\n' %(username)
            for doc in rdd.collect():
                yield doc + ',\n'
            yield "{}\n]}"
        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'
'''


@main.route('/vpn/LoginsByUser/google/<username>')
def vpnGoogleFormat(username):
    if username:
        json = analytics_engine.getVPNLoginsByUserGoogle(username)
        logging.info(json)
        return render_template('vpnGC.html', json=json)
    else:
        return 'Username unspecified.'


@main.route('/proxy/LoginsByUser/google/<username>/<date>')
def proxyGoogleFormat(username, date):
    if username and date:
        json = analytics_engine.getProxyUserMalwareHits(username, date)
        logging.info(json)
        return render_template('proxyGC.html', json=json)
    else:
        return 'Username or date unspecified.'


@main.route('/proxy/topTransfers/google/<date>')
def getProxyTopTransfers(date):
    if date:
        (jsonTable, jsonChart) = analytics_engine.getTopTransfersProxy(date)
        # logging.info(jsonTable, jsonChart)
        return render_template('proxyTopTransfers.html', jsonTable=jsonTable, jsonChart=jsonChart)
    else:
        return 'Date unspecified.'


@main.route('/search/<table>/<sdate>/<edate>/<query>')
def search(table, sdate, edate, query):
    jsonResult = analytics_engine.getSearchResults(table, sdate, edate, query)
    def generate():
        yield '{"%s": [\n' %(table)
        for doc in jsonResult.collect():
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')

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
            url_for('main.proxyGoogleFormat', username=form.name.data, date=form.date.data.strftime('%Y-%m-%d')))
    return render_template("proxy.html", form=form)


@main.route("/proxy/top/transfers", methods=('GET', 'POST'))
def proxyTopTransfers():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.getProxyTopTransfers', date=form.date.data.strftime('%Y-%m-%d')))
    return render_template("proxy.html", form=form)


@main.route("/search", methods=('GET', 'POST'))
def search_view():
    form = SearchForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.search', table=form.table.data, sdate=form.sdate.data.strftime('%Y-%m-%d'),
                                edate=form.edate.data.strftime('%Y-%m-%d'), query=form.query.data))
    return render_template("search.html", form=form)


@main.route('/')
def index():
    return render_template('index.html')


def create_app(spark_context, dataset_path):
    global analytics_engine

    analytics_engine = AnalyticsEngine(spark_context, dataset_path)

    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.secret_key = 'super secret key'

    Bootstrap(app)

    app.register_blueprint(main)

    nav.init_app(app)
    return app
