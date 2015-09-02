from flask import (
    render_template, Blueprint
)
from forms import UserDateForm, DateForm
from engine import analytics_engine

mod_proxy = Blueprint('proxy', __name__)


@mod_proxy.route("/proxy/malware/user", methods=('GET', 'POST'))
def proxy_user():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getProxyUserMalwareHits(form.name.data, form.fromdate.data.strftime('%Y-%m-%d'),
                    form.todate.data.strftime('%Y-%m-%d'))
        return render_template('display_table.html', json=json)

    return render_template("proxy.html", form=form)


@mod_proxy.route("/proxy/top/transfers", methods=('GET', 'POST'))
def proxyTopTransfers():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        (jsonTable, jsonChart) = analytics_engine.getTopTransfersProxy(form.fromdate.data.strftime('%Y-%m-%d'),
                                                                       form.todate.data.strftime('%Y-%m-%d'))
        return render_template('proxyTopTransfers.html', jsonTable=jsonTable, jsonChart=jsonChart)

    return render_template("proxy.html", form=form)
