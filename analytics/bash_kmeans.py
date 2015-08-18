from pyspark.mllib.clustering import KMeans
from pyspark.mllib.feature import Word2Vec
from pyspark.sql import SQLContext
import numpy

sqlctx = SQLContext(sc)
bashlogsDF = sqlctx.parquetFile('/user/cloudera/bashlog')
commandsDF = bashlogsDF.select(bashlogsDF.command)

# RDD of list of words in each command
commandsRDD = commandsDF.rdd.map(lambda row: row.command.split(" "))
# [[u'ssh', u'buc-0f0-as01'], [u'ssh', u'buc-0f0-cs01'], [u'ssh', u'buc-0f0-as01'], [u'ssh', u'msr-mail-inc01'],
# [u'ssh', u'msr-mail-inc02'], [u'ssh', u'216.98.54.4'], [u'exit'], [u'ssh', u'216.98.54.4'], [u'exit'], [u'ssh',
# u'mdc-ps9-psdb02']]

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
# DenseVector([-0.0672, -0.1306, -0.0428, -0.2861, -0.1339, 0.3088, 0.2711, -0.2995, -0.0435, -0.1408, -0.0537,
# -0.2757, 0.2395, -0.0026, -0.4035, -0.2496, 0.233, -0.2735, -0.0123, 0.1378, 0.1516, 0.176, 0.3047, -0.0148,
# -0.1075, -0.2471, 0.2921, -0.1233, 0.2886, 0.0551, 0.0632, -0.2558, 0.2479, -0.1969, 0.1682, 0.226, 0.0333, 0.1535,
#  0.1535, -0.1131, -0.3246, -0.0514, 0.0064, -0.0462, -0.0694, 0.2691, 0.0705, -0.4398, -0.3359, -0.0268, -0.2113,
# 0.4166, 0.3432, -0.0645, -0.2998, 0.046, 0.1678, 0.2282, 0.2237, 0.2083, 0.4318, -0.2796, 0.1348, -0.042, -0.297,
# 0.1935, 0.0151, 0.1347, -0.1085, 0.0256, -0.1162, 0.1647, -0.1022, 0.0257, 0.0097, -0.1085, -0.4927, 0.2784,
# -0.4421, -0.2632, 0.3807, -0.1806, -0.4229, -0.1617, -0.0415, 0.2298, 0.1323, 0.1979, -0.1103, 0.0607, -0.1882,
# -0.3098, -0.2402, -0.677, -0.2316, -0.3523, 0.0687, -0.3109, -0.1301, 0.501])
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
