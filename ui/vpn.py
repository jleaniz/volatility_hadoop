from flask import (
    render_template, Blueprint, Response
)
from forms import  UserForm
from engine import analytics_engine

mod_vpn = Blueprint('vpn', __name__)


@mod_vpn.route("/api/vpn/byUser/<username>")
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


@mod_vpn.route("/api/vpn/identifyUser/<date>/<remoteip>")
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


@mod_vpn.route("/vpn/user", methods=('GET', 'POST'))
def vpn_user():
    form = UserForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getVPNLoginsByUserGoogle(form.name.data)
        return render_template('vpnGC.html', json=json)

    return render_template("vpn.html", form=form)

@mod_vpn.route('/')
def index():
    return render_template('index.html')