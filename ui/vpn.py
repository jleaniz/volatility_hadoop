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

from flask import (
    render_template, Blueprint, Response
)
from forms import UserForm
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
        return render_template('DisplayTableAndCharts.html', jsonChart=json, jsonTable=json)

    return render_template("vpn.html", form=form)


@mod_vpn.route('/')
def index():
    return render_template('index.html')
