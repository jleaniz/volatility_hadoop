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

import gzip
from flask import (
    render_template, redirect, url_for, Response, make_response, Blueprint, jsonify
)
from forms import SearchForm, CustomSearchForm
from engine import analytics_engine, buildJSON
from login import access_token_required

mod_search = Blueprint('search', __name__)


@mod_search.route('/')
@access_token_required
def index():
    return render_template('search.html')


@mod_search.route('/download/<file>')
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


@mod_search.route('/search/p')
def search(request):
    if request.method == 'POST':
        jsonResult = analytics_engine.getSearchResults(request.tables, request.fromdate, request.todate, request.query, request.num)

        def generate():
            yield '{"%s": [\n' % ('search')
            for doc in jsonResult:
                yield doc + ',\n'
            yield "{}\n]}"

        return Response(generate(), mimetype='application/json')


@mod_search.route('/search/custom/<query>')
def CustomSearch(query):
    jsonResult = analytics_engine.getCustomSearchResults(query)

    def generate():
        yield '{"%s": [\n' % ('search')
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')


@mod_search.route("/search", methods=('GET', 'POST'))
@access_token_required
def search_view(request):
    Lookupform = SearchForm(csrf_enabled=False)
    schemas = [
        """bashlog
         |-- command: string (nullable = true)
         |-- exec_as: string (nullable = true)
         |-- source: string (nullable = true)
         |-- srcip: string (nullable = true)
         |-- username: string (nullable = true)
         |-- date: string (nullable = true)
        """,
        """ciscovpn
         |-- bytesrcv: string (nullable = true)
         |-- bytesxmt: string (nullable = true)
         |-- duration: string (nullable = true)
         |-- localip: string (nullable = true)
         |-- reason: string (nullable = true)
         |-- remoteip: string (nullable = true)
         |-- source: string (nullable = true)
         |-- time: string (nullable = true)
         |-- user: string (nullable = true)
         |-- date: string (nullable = true)
        """,
        """firewall
         |-- action: string (nullable = true)
         |-- dstip: string (nullable = true)
         |-- dstport: long (nullable = true)
         |-- len: long (nullable = true)
         |-- proto: string (nullable = true)
         |-- source: string (nullable = true)
         |-- srcip: string (nullable = true)
         |-- srcport: long (nullable = true)
         |-- time: string (nullable = true)
         |-- ttl: long (nullable = true)
         |-- date: string (nullable = true)
        """,
        """proxy
            urischeme, scbytes, referer, tlsver, group, agent, tlscipher, proxyip, query, clientip, contenttype, host, date, path, csbytes, time, malware, categories, action, sname, method, source, saction, scstatus, username, ciphersize, port;
        """,
        """ sccm_vuln
         |-- ResourceID: string (nullable = true)
        |-- Distinguished_Name0: string (nullable = true)
        |-- Full_Domain_Name0: string (nullable = true)
        |-- Is_Virtual_Machine0: string (nullable = true)
        |-- Name0: string (nullable = true)
        |-- Operating_System_Name_and0: string (nullable = true)
        |-- Resource_Domain_OR_Workgr0: string (nullable = true)
        |-- Site_X: string (nullable = true)
        |-- Region_X: string (nullable = true)
        |-- Zone_X: string (nullable = true)
        |-- HostFn_X: string (nullable = true)
        |-- ONBE_Gp_X: string (nullable = true)
        |-- Corp_App_X: string (nullable = true)
        |-- Exclude_X: string (nullable = true)
        |-- DisplayName0: string (nullable = true)
        |-- InstallDate0: string (nullable = true)
        |-- Publisher0: string (nullable = true)
        |-- Version0: string (nullable = true)
        |-- arch_X: string (nullable = true)
        |-- vendor_X: string (nullable = true)
        |-- t_cve_name: string (nullable = true)
        |-- cvss_score: string (nullable = true)
        |-- cvss_acc_cmpl_cat: string (nullable = true)
        |-- cvss_acc_vect_cat: string (nullable = true)
        |-- crit_X_cat: string (nullable = true)
        """,
    ]
    if request.method == 'POST':
        if Lookupform.validate_on_submit() and Lookupform.lookup.data:
            return redirect(url_for('.search/p', tables=Lookupform.tables.data, fromdate=Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                        todate=Lookupform.todate.data.strftime('%Y-%m-%d'),query=Lookupform.query.data, num=Lookupform.num.data))

        if Lookupform.validate_on_submit() and Lookupform.download.data:
            data = buildJSON(Lookupform.tables.data, Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                             Lookupform.todate.data.strftime('%Y-%m-%d'),
                             Lookupform.query.data, Lookupform.num.data)
            response = download(data)
            return response

    return render_template("search.html", form=Lookupform, schemas=schemas)


@mod_search.route("/search/custom", methods=('GET', 'POST'))
@access_token_required
def custom_search_view():
    Search = CustomSearchForm(csrf_enabled=False)

    if Search.validate_on_submit() and Search.lookup.data:
        return redirect(url_for('.CustomSearch', query=Search.query.data))

    if Search.validate_on_submit() and Search.download.data:
        data = CustomSearch(Search.query.data)
        response = download(data)
        return response

    return render_template("custom_search.html", form=Search)
