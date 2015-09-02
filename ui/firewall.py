import gzip
from flask import (
    render_template, redirect, url_for, Blueprint
)
from forms import  DateForm
from engine import analytics_engine

mod_firewall = Blueprint('search', __name__)

@mod_firewall.route('/')
def index():
    return render_template('search.html')

@mod_firewall.route("/firewall/port/stats", methods=('GET', 'POST'))
def DisplayPortStats():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        jsonChart = analytics_engine.getFirewallPortStats(form.fromdate.data.strftime('%Y-%m-%d'), form.todate.data.strftime('%Y-%m-%d'))
        #return redirect(url_for('mod_firewall.getPortStats', fromdate=form.fromdate.data.strftime('%Y-%m-%d'),
        #                        todate=form.todate.data.strftime('%Y-%m-%d')))
        return render_template('proxyTopTransfers.html', jsonTable=jsonChart, jsonChart=jsonChart)

    return render_template("search.html", form=form)
