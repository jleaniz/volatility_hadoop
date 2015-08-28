from flask_wtf import Form
from wtforms.fields import StringField, SubmitField, SelectField
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
    name = StringField(u'Username', validators=[DataRequired(message="Invalid input. Ex: jdoe")])
    submit = SubmitField(u'Lookup')


class DateForm(Form):
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    submit = SubmitField(u'Lookup')


class SearchForm(Form):
    table = SelectField(choices=[('proxysg', 'proxysg'), ('firewall', 'firewall'), ('ciscovpn', 'ciscovpn')],
                        validators=[DataRequired(message='Required field')]
                        )
    fromdate = DateField(u'From', format='%Y-%m-%d',
                         validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    todate = DateField(u'To', format='%Y-%m-%d',
                       validators=[DataRequired(message="Invalid input. Ex: 2015-01-01")])
    query = StringField(u'Query', validators=[DataRequired(message="Field required")])
    num = SelectField(
        choices=[('10', '10'), ('100', '100'), ('1000', '1000'), ('10000', '10000'), ('100000', '100000')],
        validators=[DataRequired(message='Required field')]
    )
    lookup = SubmitField(u'Lookup')
    download = SubmitField(u'Download')
