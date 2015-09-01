from flask import (
    render_template, redirect, url_for
)

from forms import UserDateForm
from app import analytics_engine, logger, main

@main.route('/api/bash/keyword/<keyword>')
def bashKeyword(keyword):
    if keyword:
        json = analytics_engine.bashKeywordSearch(keyword)
        logger.info(json)
        return render_template('display_table.html', json=json.decode('utf-8'))
    else:
        return 'Keyword or date unspecified.'


@main.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.bashKeyword', keyword=form.name.data))
    return render_template("proxy.html", form=form)
