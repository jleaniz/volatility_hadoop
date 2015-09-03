from flask import (
    render_template, Blueprint
)
from forms import  UserDateForm
from engine import analytics_engine

mod_bash = Blueprint('bash', __name__)


@mod_bash.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.bashKeywordSearch(form.name.data)
        return render_template('DisplayTable.html', json=json.decode('utf-8'))

    return render_template("bash.html", form=form)

@mod_bash.route('/')
def index():
    return render_template('index.html')
