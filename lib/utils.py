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
from functools import wraps
from flask import redirect, url_for, session
import app

def access_token_required(func):
    @wraps(func)
    def __decorator():
        if not session.get('id_token'):
            return redirect(url_for('main.login'))
        elif not app.validate_id_token(session.get('id_token')):
            return redirect(url_for('main.login'))
        return func()

    return __decorator
