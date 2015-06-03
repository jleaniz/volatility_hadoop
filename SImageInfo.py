import utils
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':

    sc = SparkContext("local", "SparkVolatility", pyFiles=['utils.py'])
#    sqlContext = SQLContext(sc)
    images = sc.textFile('/user/cloudera/imgnames.txt')

    modules = ['imageinfo']
    volatility = utils.SparkVolatility(modules)

    rdd = images.map(volatility.Execute)
    #volatilityOutput = rdd.collect() #volatilityOutput is a list of lists with the imageInfo output

    if volatility.checkPathHadoop('hdfs:///user/cloudera/mytest'):
        volatility.rmHadoop("hdfs:///user/cloudera/mytest")

    rdd.saveAsTextFile("hdfs:///user/cloudera/mytest")

    sc.stop()