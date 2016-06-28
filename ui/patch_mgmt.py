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
    render_template, Blueprint, redirect, url_for
)
from engine import analytics_engine

mod_pm_dashboard = Blueprint('patch_mgmt', __name__)


@mod_pm_dashboard.route('/')
def index():
    redirect(url_for('patch_mgmt.Dashboard'))


@mod_pm_dashboard.route("/pm/dashboard", methods=('GET', 'POST'))
def Dashboard():
    (json_most_vuln, json_most_vuln_ncsa, json_most_vuln_emea, json_most_vuln_apac, json_most_vuln_onbe,
     json_most_vuln_corp, json_most_vuln_func) = analytics_engine.pm_dashboard()

    return render_template('pm_dashboard.html', json_most_vuln=json_most_vuln,
                           json_most_vuln_ncsa=json_most_vuln_ncsa, json_most_vuln_emea=json_most_vuln_emea,
                           json_most_vuln_apac=json_most_vuln_apac, json_most_vuln_onbe=json_most_vuln_onbe,
                           json_most_vuln_corp=json_most_vuln_corp, json_most_vuln_func=json_most_vuln_func)
    # return render_template('pm_dashboard.html')
