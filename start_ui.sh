#!/bin/bash

cd /srv/srm && spark-1.6.1-bin-hadoop2.6//bin/spark-submit --master yarn --deploy-mode client --driver-cores 4 --jars /srv/srm/spark-csv_2.11-1.1.0.jar,/srv/srm/commons-csv-1.1.jar,/srv/srm/spark-streaming-flume-assembly_2.10-1.5.1.jar --py-files /srv/srm/bdsa/dist/bdsa-0.1a0-py2.6.egg,/srv/srm/spark-1.6.1-bin-hadoop2.6/python/lib/py4j-0.9-src.zip,/srv/srm/spark-1.6.1-bin-hadoop2.6/python/lib/pyspark.zip /srv/srm/bdsa/ui/app.py
