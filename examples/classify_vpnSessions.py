'''
Testing logistic regression model
to classify vpn session logins as
normal or unusual
'''

'''
from pyspark.sql import Row
from pyspark.mllib.linalg import Vectors

df = sc.parallelize([
     Row(label=1.0, features=Vectors.dense(1.0)),
     Row(label=0.0, features=Vectors.sparse(1, [], []))]).toDF()

lr = LogisticRegression(maxIter=5, regParam=0.01)

model = lr.fit(df)
model.weights
DenseVector([5.5...])
model.intercept
-2.68...

test0 = sc.parallelize([Row(features=Vectors.dense(-1.0))]).toDF()
result = model.transform(test0).head()
result.prediction
0.0

result.probability
DenseVector([0.99..., 0.00...])

result.rawPrediction
DenseVector([8.22..., -8.22...])

test1 = sc.parallelize([Row(features=Vectors.sparse(1, [0], [1.0]))]).toDF()

model.transform(test1).head().prediction
1.0
'''

from pyspark.sql import SQLContext, Row
from pyspark.mllib.linalg import Vectors

sqlctx = SQLContext(sc)

vpnlogins = sqlctx.read.load("/user/cloudera/vpn")


