from functools import wraps
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import logging
import json
import sys
import os
import random
import string
import requests
import jwt
import base64
from flask import Blueprint, redirect, url_for, Response, request, session, make_response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mod_login = Blueprint('login', __name__)


parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.getcwd()+'/ADAL_PARAMETERS')

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    adal_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')

TEMPLATE_AUTHZ_URL = ('https://login.windows.net/{}/oauth2/authorize?'+
                      'response_type=id_token+code&response_mode=form_post&client_id={}&redirect_uri={}&'+
                      'state={}&nonce={}&resource={}')


def get_AAD_pub_cert(x5t):
    response = requests.get('https://login.windows.net/common/discovery/keys')
    keys = response.json().items()[0][1]

    for key in keys:
        if key['x5t'] == x5t:
            pub_cert = '-----BEGIN CERTIFICATE-----\r\n{}\r\n-----END CERTIFICATE-----'.format(key['x5c'][0])
            return pub_cert

def validate_id_token(id_token):
    '''
    try:
        f = open(adal_parameters['idp_cert'], 'r')
        cert_str = f.read()
        f.close()
    except IOError as e:
        print('Unable to open PEM certificate')
        return False
    '''
    header = id_token.split('.')[0]
    x5t = json.loads(base64.b64decode(header))['x5t']
    cert_str = get_AAD_pub_cert(x5t)
    cert_obj = load_pem_x509_certificate(cert_str, default_backend())
    public_key = cert_obj.public_key()

    try:
        token = jwt.decode(id_token,
                           public_key,
                           algorithms=['RS256'],
                           audience=adal_parameters['clientId'])
    except Exception as e:
        return False

    return True


@mod_login.route('/login')
def login():
        auth_state = (''.join(random.SystemRandom()
                .choice(string.ascii_uppercase + string.digits)
                for _ in range(48)))

        nonce = (''.join(random.SystemRandom()
                .choice(string.ascii_uppercase + string.digits)
                for _ in range(48)))

        authorization_url = TEMPLATE_AUTHZ_URL.format(
                adal_parameters['tenant'],
                adal_parameters['clientId'],
                adal_parameters['redirect_uri'],
                auth_state,
                nonce,
                adal_parameters['resource'])

        redirect_to_AAD = redirect(authorization_url)
        response = make_response(redirect_to_AAD)
        session['auth_state'] = auth_state
        return response


@mod_login.route('/login/callback', methods=['GET', 'POST'])
def login_callback():
        # Verify AAD id_token

        id_token = request.form['id_token']

        if id_token:
                if validate_id_token(id_token):
                        session['id_token'] = id_token
                        print session.get('id_token')
                        return redirect(url_for('main.index'))
                else:
                        return Response(json.dumps({'auth': 'error: invalid token'}), mimetype='application/json')
        else:
                return Response(json.dumps({'auth': 'error: no token found'}), mimetype='application/json')


@mod_login.route('/logout')
def logout():
    session.pop('id_token', None)
    session.pop('auth_state', None)
    return redirect('https://login.microsoftonline.com/{}/oauth2/logout?post_logout_redirect_uri={}'.format(
        adal_parameters['clientId'],
        adal_parameters['index_url'],
    ))


def access_token_required(func):
    @wraps(func)
    def __decorator(*args, **kwargs):
        '''
        if not session.get('id_token'):
            return redirect(url_for('login.login'))
        elif not validate_id_token(session.get('id_token')):
            return redirect(url_for('login.login'))
        '''
        return func(*args, **kwargs)

    return __decorator
