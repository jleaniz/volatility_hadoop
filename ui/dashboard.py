from flask import (
    render_template, Blueprint
)
from engine import analytics_engine

mod_dashboard = Blueprint('dashboard', __name__)

@mod_dashboard.route('/')
def index():
    return render_template('search.html')

@mod_dashboard.route("/dashboard", methods=('GET', 'POST'))
def DisplayPortStats():
       (fw_port_stats, fw_dstip_stats, fw_srcip_stats, proxy_top_transfers) = analytics_engine.GenerateDashboard()
       return render_template('dashboard.html', fw_port_stats=fw_port_stats, fw_dstip_stats=fw_dstip_stats,
                              fw_srcip_stats=fw_srcip_stats, proxy_top_transfers=proxy_top_transfers)

