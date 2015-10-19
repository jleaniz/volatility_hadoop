from pyspark.sql import SQLContext
from pyspark.sql.functions import asc, desc

sqlctx = SQLContext(sc)

proxy = sqlctx.load('/user/cloudera/proxysg/year=2015/month=07/day=06')
otx = sqlctx.load('/user/cloudera/reputation/otx')
c2 = sqlctx.load('/user/cloudera/reputation/c2')

sqlctx.registerDataFrameAsTable(proxy, 'proxysg')
sqlctx.registerDataFrameAsTable(otx, 'otx')
sqlctx.registerDataFrameAsTable(c2, 'c2')

c2.cache()
otx.cache()

sgotx = sqlctx.sql('select proxysg.host from proxysg join otx on otx.ip=proxysg.host')
sgc2 = sqlctx.sql('select proxysg.host from proxysg join c2 on c2.host=proxysg.host')

sgall = sgotx.unionAll(sgc2)
sgall.cache()

groupcnt = sgall.groupBy(sgall.host).count().orderBy(desc('count'))

