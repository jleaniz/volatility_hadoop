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
from forms import KeywordForm, UserDateForm
from engine import analytics_engine

mod_bash = Blueprint('bash', __name__)


@mod_bash.route('/')
def index():
    return render_template('index.html')


@mod_bash.route("/bash/kmeans", methods=('GET', 'POST'))
def bash_kmeans():
    form = KeywordForm(csrf_enabled=False)
    if form.validate_on_submit():
        (command, vector, cluster, clustersDict, syms, uncommon) = analytics_engine.getCmdPrediction(form.keyword.data)
        return render_template('bash_kmeans.html', command=command, vector=vector, syms=syms, uncommon=uncommon)

    return render_template("bash.html", form=form)

@mod_bash.route("/bash/keyword", methods=('GET', 'POST'))
def bash_keyword():
    form = UserDateForm(csrf_enabled=False)
    if form.validate_on_submit():
        json = analytics_engine.bashKeywordSearch(form.name.data)
        return render_template('DisplayTable.html', json=json.decode('utf-8'))

    return render_template("bash.html", form=form)

