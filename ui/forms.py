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

from flask_wtf import Form
from wtforms.fields import StringField, SubmitField, SelectField, TextAreaField
from wtforms.fields.html5 import DateField
from wtforms.validators import DataRequired, Email


class UserForm(Form):
    name = StringField(u'VPN Username', validators=[Email(message="Invalid input. Ex: srm-ais@email.com")])
    submit = SubmitField(u'Lookup')


class UserDateForm(Form):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    name = StringField(u'Search keyword', validators=[DataRequired(message="Invalid input. Ex: jdoe")])
    submit = SubmitField(u'Lookup')


class DateForm(Form):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    submit = SubmitField(u'Lookup')


class SearchForm(Form):
    table = SelectField(choices=[('proxysg', 'proxysg'), ('firewall', 'firewall'), ('ciscovpn', 'ciscovpn')],
                        validators=[DataRequired(message='Required field')])
    tables = ['vpn', 'firewall', 'proxysg', 'bashlog']
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    query = StringField(u'Query', validators=[DataRequired(message="Field required")])
    num = SelectField(u'Limit',
                      choices=[('10', '10'), ('100', '100'), ('1000', '1000'), ('10000', '10000'),
                               ('100000', '100000')],
                      validators=[DataRequired(message='Required field')]
                      )
    lookup = SubmitField(u'Lookup')
    download = SubmitField(u'Download')


class CustomSearchForm(Form):
    query = TextAreaField(u'Query', validators=[DataRequired(message="Field required")])
    lookup = SubmitField(u'Lookup')
    download = SubmitField(u'Download')


class PathForm(Form):
    name = StringField(u'Path', validators=[DataRequired(message="Field required")])
    submit = SubmitField(u'Lookup')


class KeywordForm(Form):
    keyword = StringField(u'Keyword', validators=[DataRequired(message="Field required")])
    submit = SubmitField(u'Lookup')