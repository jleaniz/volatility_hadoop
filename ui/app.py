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
from wtforms.fields import *
from wtforms.validators import DataRequired


class UserForm(Form):
    name = StringField(u'Username', validators=[DataRequired()])
    submit = SubmitField(u'Lookup')

main = Blueprint('main', __name__)
nav = Nav()

# We're adding a navbar as well through flask-navbar. In our example, the
# navbar has an usual amount of Link-Elements, more commonly you will have a
# lot more View instances.
nav.register_element('frontend_top', Navbar(
    View('BDSA-alpha', '.index'),
    View('Dashboard', '.index'),
    View('Home', '.index'),
    View('Search', '.index'),
    Subgroup(
        'Analytics',
        Link('VPN', '/vpn/display'),
        Link('Proxy', 'https://github.com/mbr/flask-appconfig'),
        Link('Firewall', 'https://github.com/mbr/flask-debug'),
        Separator(),
        Text('Bootstrap'),
        Link('Getting started', 'http://getbootstrap.com/getting-started/'),
        Link('CSS', 'http://getbootstrap.com/css/'),
        Link('Components', 'http://getbootstrap.com/components/'),
        Link('Javascript', 'http://getbootstrap.com/javascript/'),
        Link('Customize', 'http://getbootstrap.com/customize/'),
    ),
))

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from engine import AnalyticsEngine
import json

@main.route("/vpn/LoginsByUser/<username>")
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

@main.route('/vpn/LoginsByUser/google/<username>')
def vpnGoogleFormat(username):
    if username:
        DataTable = analytics_engine.getVPNLoginsByUserGoogle(username)
        def generate():
            for row in DataTable:
                yield str(row) + '\n'
        return Response(generate(), mimetype="text/plain")

@main.route("/vpn/display", methods=('GET', 'POST'))
def vpn_display():
    form = UserForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.vpnJSON', username=form.name.data))
    return render_template("vpn.html", form=form)

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