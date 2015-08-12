from flask import Blueprint
main = Blueprint('main', __name__)

from engine import AnalyticsEngine

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from flask import Flask, request
from flask import Response

import json

@main.route("/vpn/LoginsByUser/<username>")
def generateJSONArray(username):
    if username:
        rdd = analytics_engine.getVPNLoginsByUser(username)
        def generateJSONObject(jsonDoc):
            yield jsonDoc + ',\n'
        def generate():
            yield '{"%s": [\n' %(username)
            #for doc in rdd.collect():
            #    yield doc + ',\n'
            rdd.foreach(generateJSONObject)
            yield "{}\n]}"
        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'

def create_app(spark_context, dataset_path):
    global analytics_engine

    analytics_engine = AnalyticsEngine(spark_context, dataset_path)

    app = Flask(__name__)
    app.register_blueprint(main)
    return app