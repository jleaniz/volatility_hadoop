from flask import (
    render_template, Response, make_response, url_for, redirect
)
from app import analytics_engine, main, buildJSON, buildJSONCustom
from forms import CustomSearchForm, SearchForm
import gzip

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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


@main.route('/search/<table>/<fromdate>/<todate>/<query>/<num>')
def search(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)

    def generate():
        yield '{"%s": [\n' % (table)
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')


@main.route('/search/custom/<query>')
def CustomSearch(query):
    jsonResult = analytics_engine.getCustomSearchResults(query)

    def generate():
        yield '{"%s": [\n' % ('search')
        for doc in jsonResult:
            yield doc + ',\n'
        yield "{}\n]}"

    return Response(generate(), mimetype='application/json')


@main.route("/search", methods=('GET', 'POST'))
def search_view():
    Lookupform = SearchForm(csrf_enabled=False)

    if Lookupform.validate_on_submit() and Lookupform.lookup.data:
        return redirect(
            url_for('main.search', table=Lookupform.table.data, tables=Lookupform.tables,
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


@main.route("/search/custom", methods=('GET', 'POST'))
def custom_search_view():
    Search = CustomSearchForm(csrf_enabled=False)

    if Search.validate_on_submit() and Search.lookup.data:
        return redirect(url_for('main.CustomSearch', query=Search.query.data))

    if Search.validate_on_submit() and Search.download.data:
        data = CustomSearch(Search.query.data)
        response = download(data)
        return response

    return render_template("custom_search.html", form=Search)
