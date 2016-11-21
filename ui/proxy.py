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
    render_template, Blueprint
)
from forms import UserDateForm, DateForm
from engine import analytics_engine
from login import access_token_required

mod_proxy = Blueprint('proxy', __name__)

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@mod_proxy.route("/proxy/endpoint", methods=('GET', 'POST'))
@access_token_required
def proxy_user():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getProxyUserMalwareHits(form.name.data, form.fromdate.data.strftime('%Y-%m-%d'),
                                                        form.todate.data.strftime('%Y-%m-%d'))
        return render_template('DisplayTable.html', json=json)

    return render_template("dateForm.html", form=form)


@mod_proxy.route("/proxy/top/transfers", methods=('GET', 'POST'))
@access_token_required
def proxyTopTransfers():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        (jsonTable, jsonChart) = analytics_engine.getTopTransfersProxy(form.name.data, form.fromdate.data.strftime('%Y-%m-%d'),
                                                                       form.todate.data.strftime('%Y-%m-%d'))
        return render_template('DisplayTableAndCharts.html', jsonTable=jsonTable, jsonChart=jsonChart)

    return render_template("dateForm.html", form=form)


@mod_proxy.route("/proxy/uncommon/useragent", methods=('GET', 'POST'))
@access_token_required
def proxyUncommonUserAgents():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getLeastCommonUserAgents(form.fromdate.data.strftime('%Y-%m-%d'),
                                                         form.todate.data.strftime('%Y-%m-%d'))
        return render_template('DisplayTable.html', json=json.decode('utf-8'))

    return render_template("dateForm.html", form=form)


@mod_proxy.route("/proxy/endpoint/outdated", methods=('GET', 'POST'))
@access_token_required
def proxyOutdatedEndpoints():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getOutdatedClients(form.fromdate.data.strftime('%Y-%m-%d'),
                                                   form.todate.data.strftime('%Y-%m-%d'))
        return render_template('DisplayTable.html', json=json.decode('utf-8'))

    return render_template("dateForm.html", form=form)


@mod_proxy.route("/proxy/top/visited", methods=('GET', 'POST'))
@access_token_required
def proxyMostVisitedDomains():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getMostVisitedDomains(form.fromdate.data.strftime('%Y-%m-%d'),
                                                      form.todate.data.strftime('%Y-%m-%d'))
        logger.info(json)
        return render_template('DisplayTableAndCharts.html', jsonTable=json, jsonChart=json)

    return render_template("dateForm.html", form=form)


@mod_proxy.route("/proxy/top/malware", methods=('GET', 'POST'))
@access_token_required
def proxyMostVisitedMalwareDomains():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getMostVisitedMalwareDomains(form.fromdate.data.strftime('%Y-%m-%d'),
                                                             form.todate.data.strftime('%Y-%m-%d'))
        logger.info(json)
        return render_template('DisplayTableAndCharts.html', jsonTable=json, jsonChart=json)

    return render_template("dateForm.html", form=form)


@mod_proxy.route("/proxy/top/malware/feeds", methods=('GET', 'POST'))
@access_token_required
def proxyMalwareDomainsIntel():
    form = DateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.getProxyIntelHits(form.fromdate.data.strftime('%Y-%m-%d'),
                                                  form.todate.data.strftime('%Y-%m-%d'))
        logger.info(json)
        return render_template('DisplayTableAndCharts.html', jsonTable=json, jsonChart=json)

    return render_template("dateForm.html", form=form)


@mod_proxy.route('/')
def index():
    return render_template('index.html')
