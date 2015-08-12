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
 
 
def run_server(app):
 
    # Enable WSGI access logging via Paste
    app_logged = TransLogger(app)
 
    # Mount the WSGI callable object (app) on the root directory
    cherrypy.tree.graft(app_logged, '/')
 
    # Set the configuration of the web server
    cherrypy.config.update({
        'engine.autoreload.on': True,
        'log.screen': True,
        'server.socket_port': 5432,
        'server.socket_host': '0.0.0.0'
    })
 
    # Start the CherryPy WSGI web server
    cherrypy.engine.start()
    cherrypy.engine.block()
 
 
if __name__ == "__main__":
    # Init spark context and load libraries
    sc = init_spark_context()
    dataset_path = '/user/cloudera/ciscovpn'
    app = create_app(sc, dataset_path)
 
    # start web server
    run_server(app)