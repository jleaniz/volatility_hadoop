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
from login import access_token_required

mod_dashboard = Blueprint('dashboard', __name__)


@mod_dashboard.route('/')
@access_token_required
def index():
    redirect(url_for('dashboard.Dashboard'))


@mod_dashboard.route("/dashboard", methods=('GET', 'POST'))
@access_token_required
def Dashboard():
    (fw_port_stats, fw_dstip_stats, fw_srcip_stats) = analytics_engine.GenerateDashboard()
    return render_template('dashboard.html', fw_port_stats=fw_port_stats, fw_dstip_stats=fw_dstip_stats,
                           fw_srcip_stats=fw_srcip_stats)
