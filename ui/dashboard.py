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
    render_template, Blueprint, request, Response
)
from engine import analytics_engine
from login import access_token_required
from forms import UserForm

mod_dashboard = Blueprint('dashboard', __name__)


@mod_dashboard.route("/dashboard/birdseye", methods=('GET', 'POST'))
@access_token_required
def birdseye():
    Lookupform = UserForm(csrf_enabled=False)
    if request.method == 'POST':
        if Lookupform.validate_on_submit() and Lookupform.lookup.data:
            (json_fw_data, json_proxy_data, bash_data, vpn_activtiy, patch_data) = analytics_engine.birdseye(
                request.form.get('name')
            )

            return render_template('birdseye.html', json_proxy_data=json_proxy_data, json_fw_data=json_fw_data)

    return render_template("vpn.html", form=Lookupform)

@mod_dashboard.route("/dashboard/fw", methods=('GET', 'POST'))
@access_token_required
def fw_dashboard():
    (fw_port_stats, fw_dstip_stats, fw_srcip_stats) = analytics_engine.GenerateDashboard()
    return render_template('fw_dashboard.html', fw_port_stats=fw_port_stats, fw_dstip_stats=fw_dstip_stats,
                           fw_srcip_stats=fw_srcip_stats)


@mod_dashboard.route("/dashboard/pm", methods=('GET', 'POST'))
@access_token_required
def pm_dashboard():
    (json_per_site_vuln, json_most_vuln, json_most_vuln_ncsa, json_most_vuln_emea, json_most_vuln_apac, json_most_vuln_onbe,
     json_most_vuln_corp, json_most_vuln_func) = analytics_engine.pm_dashboard()

    return render_template('pm_dashboard.html', json_most_vuln=json_most_vuln,
                           json_most_vuln_ncsa=json_most_vuln_ncsa, json_most_vuln_emea=json_most_vuln_emea,
                           json_most_vuln_apac=json_most_vuln_apac, json_most_vuln_onbe=json_most_vuln_onbe,
                           json_most_vuln_corp=json_most_vuln_corp, json_most_vuln_func=json_most_vuln_func,
                           json_per_site_vuln=json_per_site_vuln)
    # return render_template('pm_dashboard.html')


@mod_dashboard.route("/dashboard/pm/<region>/<sft>", methods=('GET', 'POST'))
@access_token_required
def pm_dashboard_hosts(region, sft):
    json = analytics_engine.pm_get_java_hosts(region, sft)
    return render_template('DisplayTable.html', json=json)
