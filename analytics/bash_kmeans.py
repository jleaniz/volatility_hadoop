from pyspark.mllib.clustering import KMeans
from pyspark.mllib.feature import Word2Vec
from pyspark.sql import SQLContext
import numpy

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
commandsList = commandsListRDD.collect()
vectorsList = []

for command in commandsList:
    try:
        vectorsList.append(numpy.array(model.transform(command)))
    except ValueError:
        pass

kmdata = sc.parallelize(vectorsList, 1024)
# kmdata = sc.parallelize( (numpy.array(model.transform(command[0])) for command in commandsList), 1024)

# Build the model (cluster the data using KMeans)
clusters = KMeans.train(kmdata, 100, maxIterations=10, runs=10, initializationMode="random")

'''
# Find synonyms for ssh
model.findSynonyms("ssh", 2)
# [(u'ping', 0.70947927236557007), (u'exit', 0.67307734489440918)]

# Find cluster for a synonym of ssh
testVector = model.transform("ping")
clusters.predict(numpy.array(testVector))


for command in commandsList:
    try:
        vector = model.transform(command[0])
        print "Cmd: %s Cluster: %d" % (command[0], clusters.predict(numpy.array(vector)))
    except:
        pass

# syms = model.findSynonyms("pwd", 5)
# print [s[0] for s in syms]
'''
