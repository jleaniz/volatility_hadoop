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
    render_template, Blueprint
)
from forms import DateForm
from engine import analytics_engine

mod_firewall = Blueprint('firewall', __name__)


@mod_firewall.route('/')
def index():
    return render_template('search.html')


@mod_firewall.route("/firewall/port/stats", methods=('GET', 'POST'))
def DisplayPortStats():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        jsonChart = analytics_engine.getFirewallPortStats(form.fromdate.data.strftime('%Y-%m-%d'),
                                                          form.todate.data.strftime('%Y-%m-%d'))
        return render_template('DisplayTableAndCharts.html', jsonTable=jsonChart, jsonChart=jsonChart)

    return render_template("dateForm.html", form=form)


@mod_firewall.route("/firewall/ip/stats", methods=('GET', 'POST'))
def DisplayIPStats():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        jsonChart = analytics_engine.getFirewallIPStats(form.fromdate.data.strftime('%Y-%m-%d'),
                                                        form.todate.data.strftime('%Y-%m-%d'))
        return render_template('DisplayTableAndCharts.html', jsonTable=jsonChart, jsonChart=jsonChart)

    return render_template("dateForm.html", form=form)
