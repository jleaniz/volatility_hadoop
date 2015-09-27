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

mod_search = Blueprint('search', __name__)


@mod_search.route('/')
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


@mod_search.route('/search/<table>/<fromdate>/<todate>/<query>/<num>')
def search(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)
    '''
    def generate():
        yield '{"%s": [\n' % (table)
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')
    '''
    return jsonify(jsonResult)

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
def search_view():
    Lookupform = SearchForm(csrf_enabled=False)

    if Lookupform.validate_on_submit() and Lookupform.lookup.data:
        return redirect(
            url_for('.search', table=Lookupform.table.data, tables=Lookupform.tables,
                    fromdate=Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                    todate=Lookupform.todate.data.strftime('%Y-%m-%d'), query=Lookupform.query.data,
                    num=Lookupform.num.data))

    if Lookupform.validate_on_submit() and Lookupform.download.data:
        data = buildJSON(Lookupform.table.data, Lookupform.fromdate.data.strftime('%Y-%m-%d'),
                         Lookupform.todate.data.strftime('%Y-%m-%d'),
                         Lookupform.query.data, Lookupform.num.data)
        response = download(data)
        return response

    return render_template("search.html", form=Lookupform)


@mod_search.route("/search/custom", methods=('GET', 'POST'))
def custom_search_view():
    Search = CustomSearchForm(csrf_enabled=False)

    if Search.validate_on_submit() and Search.lookup.data:
        return redirect(url_for('.CustomSearch', query=Search.query.data))

    if Search.validate_on_submit() and Search.download.data:
        data = CustomSearch(Search.query.data)
        response = download(data)
        return response

    return render_template("custom_search.html", form=Search)
