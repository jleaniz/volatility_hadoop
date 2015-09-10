from pyspark.mllib.clustering import KMeans
from pyspark.mllib.feature import Word2Vec
from pyspark.sql import SQLContext
import numpy
from math import sqrt

sqlctx = SQLContext(sc)
bashlogsDF = sqlctx.parquetFile('/user/cloudera/bashlog')
commandsDF = bashlogsDF.select(bashlogsDF.command)

# RDD of list of words in each command
# Review: each command should be considered a "word" instead of each command + arg being an individual word
commandsRDD = commandsDF.rdd.map(lambda row: row.command.split("\n"))

# Convect commands in commandsRDD to vectors.
w2v = Word2Vec()
model = w2v.fit(commandsRDD)

commandsListRDD = commandsDF.rdd.flatMap(lambda row: row.command.split("\n"))
commandsList = sc.parallelize(commandsListRDD.take(100000)).collect()
vectorsList = []

for command in commandsList:
    try:
        vectorsList.append(numpy.array(model.transform(command)))
    except ValueError:
        pass

kmdata = sc.parallelize(vectorsList, 1024)
# kmdata = sc.parallelize( (numpy.array(model.transform(command[0])) for command in commandsList), 1024)

k = sqrt(len(vectorsList)/2)

# Build the model (cluster the data using KMeans)
clusters = KMeans.train(kmdata, k, maxIterations=10, runs=10, initializationMode="random")

d = dict()
for command in commandsList:
        try:
            vector = model.transform(command)
            cluster = clusters.predict(numpy.array(vector))
            #print "Cmd: %s Cluster: %d" % (command, cluster)
            d.setdefault(cluster, [])
            d[cluster].append(command)
        except:
            pass
