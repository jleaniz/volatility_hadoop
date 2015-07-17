#
# This file is part of BDSA (Big Data Security Analytics)
#
# Foobar is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Foobar is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
    sc = SparkContext("local[8]", "SparkVolatility", pyFiles=['parser.py'])
    sqlContext = SQLContext(sc)

    df = sqlContext.load('fw/log')
    sqlContext.registerDataFrameAsTable(df, "fwlog")
    data = sqlContext.sql(
        "SELECT dstip, count(*) as hits FROM fwlog WHERE action LIKE 'DENY' GROUP BY dstip ORDER BY hits DESC")
    data.cache()
    data.show()
    sc.stop()
