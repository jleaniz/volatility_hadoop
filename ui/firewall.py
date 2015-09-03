from flask import (
    render_template, Blueprint
)
from forms import  DateForm
from engine import analytics_engine

mod_firewall = Blueprint('firewall', __name__)

@mod_firewall.route('/')
def index():
    return render_template('search.html')

@mod_firewall.route("/firewall/port/stats", methods=('GET', 'POST'))
def DisplayPortStats():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        jsonChart = analytics_engine.getFirewallPortStats(form.fromdate.data.strftime('%Y-%m-%d'), form.todate.data.strftime('%Y-%m-%d'))
        return render_template('proxyTopTransfers.html', jsonTable=jsonChart, jsonChart=jsonChart)

    return render_template("proxy.html", form=form)
