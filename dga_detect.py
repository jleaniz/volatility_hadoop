from pyspark.ml import Pipeline
from pyspark.ml.classification import RandomForestClassifier, LogisticRegression, MultilayerPerceptronClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator, RegressionEvaluator, MulticlassClassificationEvaluator
from pyspark.ml.tuning import ParamGridBuilder, CrossValidator
from pyspark.ml.feature import StringIndexer
from pyspark.mllib.linalg import Vectors
from pyspark.sql.types import *
from pyspark.sql import Row
from pyspark import SQLContext
import re
import math
import numpy as np
import pandas as pd
import sklearn.feature_extraction

from collections import Counter

sqlctx = SQLContext(sc)

re_ipaddr = re.compile('(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')

schema = StructType([
    StructField("domain", StringType(), True),
    StructField("category", StringType(), True),
    StructField("length", DoubleType(), True),
    StructField("entropy", DoubleType(), True)
])

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

def features_to_vec(length, entropy, alexa_grams, word_grams):
    high_entropy = 0.0
    high_length = 0.0
    if entropy > 3.5: high_entropy = 1.0
    if length > 30: high_length = 1.0
    return Vectors.dense(length, entropy, high_entropy, high_length, alexa_grams, word_grams)


#dga_domains = sc.textFile("/user/cloudera/dga.txt")
#dga_domains = dga_domains.map(lambda x: (x, "dga", float(len(x)), entropy(x)))
#dga_domains_df = sqlctx.createDataFrame(dga_domains, schema).dropna().distinct().cache()

words = sc.textFile("/user/cloudera/words.txt")
words = words.map(lambda x: (x, "dict", float(len(x)), entropy(x)))
words_df = sqlctx.createDataFrame(words, schema).dropna().distinct().cache()

dga_domains = sc.textFile("/user/cloudera/c_domains_*")
dga_domains = dga_domains.map(lambda x: (x, "dga", float(len(x)), entropy(x)))
dga_domains_df = sqlctx.createDataFrame(dga_domains, schema).dropna().distinct().cache()

alexa_domains = sqlctx.read.format('com.databricks.spark.csv').options(header='false', inferschema='true').load(
    'alexa_100k.csv')\
    .map(lambda x: (x[1], "legit", float(len(x[1])), entropy(x[1])))
alexa_domains_df = sqlctx.createDataFrame(alexa_domains, schema).dropna().distinct().cache()

alexa_domains_1M = sqlctx.read.format('com.databricks.spark.csv').options(header='false', inferschema='true').load(
    'alexa_1M.csv')\
    .map(lambda x: (x[1], "legit", float(len(x[1])), entropy(x[1])))
alexa_domains_1M = sqlctx.createDataFrame(alexa_domains_1M, schema).distinct().cache()

proxy_test_df = sqlctx.read.parquet('/user/cloudera/proxysg/date=2015-12-*').select('host').dropna().distinct()\
    .filter('host not like "www.%"')\
    .filter('host like "%.%"')\
    .map(lambda x: Row(host=x.host, length=len(x.host), entropy=entropy(x.host)))\
    .filter(lambda x: re.search(re_ipaddr, x.host) is None)\
    .toDF().filter('length > 6').cache()

domains_df = dga_domains_df.unionAll(alexa_domains_1M).cache()
domains_df_train, domains_df_test = domains_df.randomSplit([0.7, 0.3])
domains_df_train.cache()
domains_df_test.cache()

alexa_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-4, max_df=1.0)
dict_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-5, max_df=1.0)

alexa_dataframe = alexa_domains_df.toPandas()
word_dataframe = words_df.toPandas()

pd_domains_train = domains_df_train.toPandas()
#pd_domains_train = pd_domains_train[pd_domains_train['length'] > 6]
pd_domains_test = domains_df_test.toPandas()
#pd_domains_cnc_test = dga_domains_cnc_df.toPandas()
alexa_test = alexa_domains_1M.toPandas()
pd_proxy_test = proxy_test_df.toPandas()

counts_matrix = alexa_vc.fit_transform(alexa_dataframe['domain'])
alexa_counts = np.log10(counts_matrix.sum(axis=0).getA1())
counts_matrix = dict_vc.fit_transform(word_dataframe['domain'])
dict_counts = np.log10(counts_matrix.sum(axis=0).getA1())
pd_domains_train['alexa_grams'] = alexa_counts * alexa_vc.transform(pd_domains_train['domain']).T
pd_domains_train['word_grams'] = dict_counts * dict_vc.transform(pd_domains_train['domain']).T
pd_domains_test['alexa_grams'] = alexa_counts * alexa_vc.transform(pd_domains_test['domain']).T
pd_domains_test['word_grams'] = dict_counts * dict_vc.transform(pd_domains_test['domain']).T
#pd_domains_cnc_test['alexa_grams'] = alexa_counts * alexa_vc.transform(pd_domains_cnc_test['domain']).T
#pd_domains_cnc_test['word_grams'] = dict_counts * dict_vc.transform(pd_domains_cnc_test['domain']).T
alexa_test['alexa_grams'] = alexa_counts * alexa_vc.transform(alexa_test['domain']).T
alexa_test['word_grams'] = dict_counts * dict_vc.transform(alexa_test['domain']).T
pd_proxy_test['alexa_grams'] = alexa_counts * alexa_vc.transform(pd_proxy_test['host']).T
pd_proxy_test['word_grams'] = dict_counts * dict_vc.transform(pd_proxy_test['host']).T

domains_df_train_f = sqlctx.createDataFrame(pd_domains_train)
domains_df_train_f = domains_df_train_f.map(
    lambda row: Row(**dict(row.asDict(), features=features_to_vec(row.length, row.entropy, row.alexa_grams, row.word_grams)))).toDF()

domains_df_test_f = sqlctx.createDataFrame(pd_domains_test)
domains_df_test_f = domains_df_test_f.map(
    lambda row: Row(**dict(row.asDict(), features=features_to_vec(row.length, row.entropy, row.alexa_grams, row.word_grams)))).toDF()

#domains_df_test_cnc_f = sqlctx.createDataFrame(pd_domains_cnc_test)
#domains_df_test_cnc_f = domains_df_test_cnc_f.map(
#    lambda row: Row(**dict(row.asDict(), features=features_to_vec(row.length, row.entropy, row.alexa_grams, row.word_grams)))).toDF()

alexa_test_f = sqlctx.createDataFrame(alexa_test)
alexa_test_f = alexa_test_f.map(
    lambda row: Row(**dict(row.asDict(), features=features_to_vec(row.length, row.entropy, row.alexa_grams, row.word_grams)))).toDF()

proxy_test_f = sqlctx.createDataFrame(pd_proxy_test)
proxy_test_f = proxy_test_f.map(
    lambda row: Row(**dict(row.asDict(), features=features_to_vec(row.length, row.entropy, row.alexa_grams, row.word_grams)))).toDF()

domains_df_train_f.cache()
#domains_df_test_f.cache()
#domains_df_test_cnc_f.cache()
alexa_test_f.cache()
proxy_test_f.cache()
'''
paramGrid = ParamGridBuilder()\
  .addGrid(rf.numTrees, [5, 15, 25, 35])\
  .addGrid(rf.maxDepth, [2, 5, 15, 20])\
  .build()
paramGrid = ParamGridBuilder()\
  .addGrid(rf.regParam, [0.2, 0.5, 0.05])\
  .addGrid(rf.elasticNetParam, [0.0, 0.5, 1.0])\
  .addGrid(rf.maxIter, [100, 10, 50])\
  .build()
'''

stringIndexer = StringIndexer(inputCol="category", outputCol="label")
#rf = RandomForestClassifier(featuresCol="features", labelCol="label")
rf = MultilayerPerceptronClassifier(featuresCol="features", labelCol="label")
evaluator = RegressionEvaluator(predictionCol="prediction",labelCol="label")
pipeline = Pipeline(stages=[stringIndexer, rf])

paramGrid = ParamGridBuilder()\
  .addGrid(rf.layers, [[6, 10, 2],
                       [6, 3, 2],
                       [6, 50, 2],
                       [6, 100, 2]])\
  .addGrid(rf.maxIter, [10, 50, 100])\
  .build()

cv = CrossValidator(estimator=pipeline, evaluator=evaluator, estimatorParamMaps=paramGrid, numFolds=10)
cvModel = cv.fit(domains_df_train_f)

cvModel.bestModel.transform(domains_df_test_f).show()
cvModel.bestModel.transform(alexa_test_f).show()

proxytest = cvModel.transform(proxy_test_f)
proxytest = proxytest.filter('prediction=0.0').where('host like "%.%"').distinct()
proxytest.cache()

test = sqlctx.read.parquet('/user/cloudera/proxysg/date=2016-02-1*').select('host','clientip','proxyip','username').distinct()
test.cache()

match = proxytest.join(test,'host')

#rf_model = rf.fit(domains_df_train_f)
#rf_model.transform(dga_c_domains_df_f).show()
