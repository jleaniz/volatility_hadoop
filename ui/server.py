import cherrypy
from paste.translogger import TransLogger
from app import create_app
from pyspark import SparkContext, SparkConf
from config import config as conf


def init_spark_context():
    # load spark context
    appConfig = conf.Config()
    # IMPORTANT: pass aditional Python modules to each worker
    sc = SparkContext(conf=appConfig.setSparkConf())

    return sc

sc = init_spark_context()

def run_server(app):
    # Enable WSGI access logging via Paste
    app_logged = TransLogger(app)

    # Mount the WSGI callable object (app) on the root directory
    cherrypy.tree.graft(app_logged, '/')

    # Set the configuration of the web server
    cherrypy.config.update({
        'engine.autoreload.on': True,
        'log.screen': True,
        'response.stream': True,
        'response.timeout': 3600,
        # 'server.ssl_module': 'builtin',
        'server.socket_port': 5432,
        'server.socket_host': '0.0.0.0'
    })
    # cherrypy.server.ssl_certificate = "cert.pem"
    # cherrypy.server.ssl_private_key = "privkey.pem"
    # Start the CherryPy WSGI web server
    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == "__main__":
    # Init spark context and load libraries
    app = create_app(sc)

    # start web server
    run_server(app)
