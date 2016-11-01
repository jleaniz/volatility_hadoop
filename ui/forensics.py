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
from forms import PathForm
from engine import analytics_engine
from app import access_token_required
mod_for = Blueprint('forensics', __name__)


@mod_for.route('/')
@access_token_required
def index():
    return render_template('forensics.html')


@mod_for.route("/forensics/timeline", methods=('GET', 'POST'))
@access_token_required
def TimelineStats():
    form = PathForm(csrf_enabled=False)
    if form.validate_on_submit():
        jsonChartDF, jsonChartFT = analytics_engine.FSTimelineStats(form.name.data)
        return render_template('timeline.html', jsonChartDF=jsonChartDF, jsonChartFT=jsonChartFT)

    return render_template("forensics.html", form=form)
