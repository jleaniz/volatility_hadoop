from flask import (
    render_template, redirect, url_for, Blueprint
)
from forms import  UserDateForm
from engine import analytics_engine

mod_bash = Blueprint('bash', __name__)


@mod_bash.route('/api/bash/keyword/<keyword>')
def bashKeyword(keyword):
    if keyword:
        json = analytics_engine.bashKeywordSearch(keyword)
        return render_template('display_table.html', json=json.decode('utf-8'))
    else:
        return 'Keyword or date unspecified.'


@mod_bash.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(
            url_for('main.bashKeyword', keyword=form.name.data))
    return render_template("proxy.html", form=form)
