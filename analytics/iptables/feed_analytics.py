#
# This file is part of BDSA (Big Data Security Analytics)
#
# BDSA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# BDSA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with BDSA.  If not, see <http://www.gnu.org/licenses/>.
#
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
    sc = SparkContext("local[8]", "SparkVolatility")
sqlctx = SQLContext(sc)
df = sqlctx.load('BlueCoat/accessLog')
sqlctx.registerDataFrameAsTable(df, 'bluecoat')
df2 = sqlctx.load('reputation/c2')
sqlctx.registerDataFrameAsTable(df2, 'c2')
df3 = sqlctx.load('fw/log')
sqlctx.registerDataFrameAsTable(df3, 'fw')
test = sqlctx.sql(
    'SELECT srcip, dstip, dstport, action, count(*) as hits FROM fw WHERE action LIKE "%DENY%" AND dstport LIKE "3389" '
    'GROUP BY srcip, dstip, dstport, action ORDER BY hits DESC')
test.cache()
for i in test.take(100):
    print i
