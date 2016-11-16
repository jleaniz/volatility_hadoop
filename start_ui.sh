#!/bin/bash

../spark-2.0.1-bin-hadoop2.6/bin/spark-submit --master yarn --deploy-mode client --queue root.llama --py-files GeoIP.dat,GeoIP.so,libGeoIP.so.1,pool.xml,../spark-2.0.1-bin-hadoop2.6/conf/hive-site.xml,dist/bdsa-0.1_alpha-py2.6.egg ui/app.py