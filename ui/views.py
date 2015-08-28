import gzip
import forms
from flask import (
    Flask, request, render_template, flash, redirect, url_for, Response, Blueprint, make_response, abort
)

from forms import DateForm, SearchForm, UserDateForm, UserForm
from app import main, buildJSON

@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e.message)


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e.message)


@main.route('/download/<file>')
def download(content):
    f = gzip.open('/tmp/results.gz', 'wb')
    try:
        for line in content:
            f.write(line)
    finally:
        f.close()

    r = open('/tmp/results.gz', 'rb')
    try:
        buf = r.read()
    finally:
        r.close()

    response = make_response(buf)
    # This is the key: Set the right header for the response
    # to be downloaded, instead of just printed on the browser
    response.headers["Content-Disposition"] = "attachment; filename=results.gz"
    return response


@main.route("/vpn/user", methods=('GET', 'POST'))
def vpn_user():
    form = UserForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.vpnGoogleFormat', username=form.name.data))
    return render_template("vpn.html", form=form)


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


@main.route("/search", methods=('GET', 'POST'))
def search_view():
    Lookupform = SearchForm(csrf_enabled=False)

    if Lookupform.validate_on_submit() and Lookupform.lookup.data:
        return redirect(
            url_for('main.search', table=Lookupform.table.data, fromdate=Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                    todate=Lookupform.todate.data.strftime('%Y-%m-%d'), query=Lookupform.query.data,
                    num=Lookupform.num.data))
    if Lookupform.validate_on_submit() and Lookupform.download.data:
        data = buildJSON(Lookupform.table.data, Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                         Lookupform.todate.data.strftime('%Y-%m-%d'),
                         Lookupform.query.data, Lookupform.num.data)
        response = download(data)
        return response

    return render_template("search.html", form=Lookupform)

@main.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.bashKeyword', keyword=form.name.data ))
    return render_template("proxy.html", form=form)


@main.route('/')
def index():
    return render_template('index.html')
