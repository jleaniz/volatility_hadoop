from pyspark.mllib.clustering import KMeans
from pyspark.mllib.feature import Word2Vec
from pyspark.sql import SQLContext
import numpy

sqlctx = SQLContext(sc)
bashlogsDF = sqlctx.parquetFile('/user/cloudera/bashlog')
commandsDF = bashlogsDF.select(bashlogsDF.command)

# RDD of list of words in each command
# Review: each command should be considered a "word" instead of each command + arg being an individual word
commandsRDD = commandsDF.rdd.map(lambda row: row.command.split(" "))

# Convect commands in commandsRDD to vectors.
model = Word2Vec().fit(commandsRDD)

commandsList = commandsRDD.collect()
vectorsList = []

try:
    for command in commandsList:
        vectorsList.append(model.transform(command[0]))
except ValueError:
    pass

data = sc.parallelize(vectorsList)
parsedData = data.map(lambda x: numpy.array(x))

# Build the model (cluster the data using KMeans)
clusters = KMeans.train(parsedData, 100, maxIterations=10, runs=10, initializationMode="random")

# Find the cluster for "ssh"
testVector = model.transform("ssh")
clusters.predict(numpy.array(testVector))

'''
# Find synonyms for ssh
model.findSynonyms("ssh", 2)
# [(u'ping', 0.70947927236557007), (u'exit', 0.67307734489440918)]

# Find cluster for a synonym of ssh
testVector = model.transform("ping")
clusters.predict(numpy.array(testVector))
'''

try:
    for command in commandsList:
        vector = model.transform(command[0])
        print "Cmd: %s Cluster: %d" % (command[0], clusters.predict(numpy.array(vector)))
except:
    pass

# syms = model.findSynonyms("pwd", 5)
# print [s[0] for s in syms]
