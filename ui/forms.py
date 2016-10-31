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

from flask_wtf import FlaskForm
from wtforms.fields import StringField, SubmitField, SelectField, TextAreaField, SelectMultipleField
from wtforms.fields.html5 import DateField
from wtforms.validators import DataRequired, Email


class UserForm(FlaskForm):
    name = StringField(u'VPN Username', validators=[Email(message="Invalid input. Ex: srm-ais@email.com")])
    lookup = SubmitField(u'Lookup')


class UserDateForm(FlaskForm):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    name = StringField(u'Search keyword', validators=[DataRequired(message="Invalid input. Ex: jdoe")])
    lookup = SubmitField(u'Lookup')


class DateForm(FlaskForm):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    lookup = SubmitField(u'Lookup')


class SearchForm(FlaskForm):
    tables = SelectMultipleField(u'Tables',
                                 choices=[('firewall', 'firewall'), ('proxysg', 'proxysg'), ('bash', 'bash'),
                                          ('ciscovpn', 'ciscovpn'), ('sccm_vuln', 'sccm_vuln'), ('otx', 'otx'), ('c2', 'c2')],
                                 validators=[DataRequired(message='Required field')])
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    query = TextAreaField(u'Query', validators=[DataRequired(message="Field required")])
    num = SelectField(u'Limit',
                      choices=[('10', '10'), ('100', '100'), ('1000', '1000'), ('10000', '10000'),
                               ('100000', '100000')],
                      validators=[DataRequired(message='Required field')]
                      )
    lookup = SubmitField(u'Lookup')
    download = SubmitField(u'Download')


class CustomSearchForm(FlaskForm):
    query = TextAreaField(u'Query', validators=[DataRequired(message="Field required")])
    lookup = SubmitField(u'Lookup')
    download = SubmitField(u'Download')


class PathForm(FlaskForm):
    name = StringField(u'Path', validators=[DataRequired(message="Field required")])
    lookup = SubmitField(u'Lookup')


class KeywordForm(FlaskForm):
    keyword = StringField(u'Keyword', validators=[DataRequired(message="Field required")])
    lookup = SubmitField(u'Lookup')
