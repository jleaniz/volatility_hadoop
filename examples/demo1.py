#../spark-1.5.1-bin-testbuild/bin/pyspark --master spark://mtl-ah374.domain.org:7077 --total-executor-cores 8 --executor-cores 8 --executor-memory 4g --driver-memory 2g --conf spark.driver.maxResultSize=2g --files GeoIP.dat --jars /home/cloudera/spark-csv/target/scala-2.11/spark-csv_2.11-1.1.0.jar,/home/cloudera/spark-csv/target/scala-2.11/commons-csv-1.1/commons-csv-1.1.jar

from pyspark.sql.types import Row
from pyspark.sql import SQLContext
from pyspark.sql.functions import asc, desc
import GeoIP

ctx = SQLContext(sc)

adlocation = ctx.read.format('com.databricks.spark.csv')\
    .options(header='true',inferschema='true').load('ad.csv').filter('c not like ""')

adlocation.printSchema()
adlocation.cache()

vpn = ctx.read.load('/user/cloudera/ciscovpn')
vpn.printSchema()
vpn.cache()

def func(x):
    gi = GeoIP.open("GeoIP.dat",GeoIP.GEOIP_MEMORY_CACHE)
    cc = gi.country_code_by_addr(x.remoteip)
    return Row(bytesrcv=x.bytesrcv, bytesxmt=x.bytesxmt, duration=x.duration, localip=x.localip, reason=x.reason,
               remoteip=x.remoteip, source=x.source, time=x.time, user=x.user, date=x.date, remoteipcc=cc)

vpnDF = vpn.map(func).toDF()
joinDF = vpnDF.join(adlocation, vpnDF.user == adlocation.EmailAddress)
joinDF.cache()

fromOtherLocations = joinDF.filter("remoteipcc <> c")
cntLoginExtLocation = fromOtherLocations.count()

groupDF = fromOtherLocations.groupBy(fromOtherLocations.user, fromOtherLocations.remoteip, fromOtherLocations.remoteipcc, fromOtherLocations.c)\
    .count()\
    .orderBy(desc('count'))

groupDF.cache()

countbyCountry = fromOtherLocations.groupBy(groupDF.user, groupDF.remoteipcc).count().orderBy(desc('count'))


