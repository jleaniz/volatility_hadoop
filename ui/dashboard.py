from flask import (
    render_template, Blueprint, redirect, url_for
)
from engine import analytics_engine

mod_dashboard = Blueprint('dashboard', __name__)


@mod_dashboard.route('/')
def index():
    redirect(url_for('dashboard.Dashboard'))


@mod_dashboard.route("/dashboard", methods=('GET', 'POST'))
def Dashboard():
    (fw_port_stats, fw_dstip_stats, fw_srcip_stats) = analytics_engine.GenerateDashboard()
    return render_template('dashboard.html', fw_port_stats=fw_port_stats, fw_dstip_stats=fw_dstip_stats,
                           fw_srcip_stats=fw_srcip_stats)
