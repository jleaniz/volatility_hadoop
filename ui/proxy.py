from app import analytics_engine, main

from flask import (
    render_template, redirect, url_for
)

from forms import DateForm, UserDateForm

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@main.route('/proxy/LoginsByUser/google/<username>/<fromdate>/<todate>')
def proxyGoogleFormat(username, fromdate, todate):
    if username and fromdate and todate:
        json = analytics_engine.getProxyUserMalwareHits(username, fromdate, todate)
        logging.info(json)
        return render_template('display_table.html', json=json)
    else:
        return 'Username or date unspecified.'


@main.route('/proxy/topTransfers/google/<fromdate>/<todate>')
def getProxyTopTransfers(fromdate, todate):
    if fromdate and todate:
        (jsonTable, jsonChart) = analytics_engine.getTopTransfersProxy(fromdate, todate)
        # logging.info(jsonTable, jsonChart)
        return render_template('proxyTopTransfers.html', jsonTable=jsonTable, jsonChart=jsonChart)
    else:
        return 'Date unspecified.'


@main.route("/proxy/malware/user", methods=('GET', 'POST'))
def proxy_user():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.proxyGoogleFormat', username=form.name.data, fromdate=form.fromdate.data.strftime('%Y-%m-%d'),
                    todate=form.todate.data.strftime('%Y-%m-%d')))
    return render_template("proxy.html", form=form)


@main.route("/proxy/top/transfers", methods=('GET', 'POST'))
def proxyTopTransfers():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.getProxyTopTransfers', fromdate=form.fromdate.data.strftime('%Y-%m-%d'),
                                todate=form.todate.data.strftime('%Y-%m-%d')))
    return render_template("proxy.html", form=form)
