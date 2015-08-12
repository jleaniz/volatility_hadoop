from flask import Flask, request, render_template, flash
from flask import Response
from flask import Blueprint
from flask_bootstrap import __version__ as FLASK_BOOTSTRAP_VERSION
from flask_nav.elements import Navbar, View, Subgroup, Link, Text, Separator
from flask_bootstrap import Bootstrap
from flask_nav import Nav
from flask_wtf import Form
from wtforms.fields import *
from wtforms.validators import Required, Email
from markupsafe import escape


class UserForm(Form):
    name = TextField(u'Your name', validators=[Required()])
    submit = SubmitField(u'Signup')

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
        Link('VPN', 'vpn/display'),
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
def generateJSONArray(username):
    if username:
        rdd = analytics_engine.getVPNLoginsByUser(username)
        def generate():
            yield '{"%s": [\n' %(username)
            for doc in rdd.collect():
                yield doc + ',\n'
            #rdd.foreach(generateJSONObject)
            yield "{}\n]}"
        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'

@main.route("/vpn/display")
def vpn_display():
    form = UserForm()
    if form.validate_on_submit():
        # We don't have anything fancy in our application, so we are just
        # flashing a message when a user completes the form successfully.
        #
        # Note that the default flashed messages rendering allows HTML, so
        # we need to escape things if we input user values:
        flash('Hello, %s. You have successfully signed up' %(escape(form.name.data)))

    return render_template("vpn.html", form=form)

# Our index-page just shows a quick explanation. Check out the template
# "templates/index.html" documentation for more details.
@main.route('/')
def index():
    return render_template('index.html')

def create_app(spark_context, dataset_path):
    global analytics_engine

    analytics_engine = AnalyticsEngine(spark_context, dataset_path)

    app = Flask(__name__)

    Bootstrap(app)

    app.register_blueprint(main)

    nav.init_app(app)

    return app