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
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def getClientsByTransfer(sc, parquetFiles, number, year, month, day):
    print sc
    # Creat Spark SQL context
    sqlctx = SQLContext(sc)
    # Load files into a DataFrame
    df = sqlctx.load(parquetFiles)
    # Register temporary in-memory table
    sqlctx.registerDataFrameAsTable(df, 'sgos')

    # Query using Spark SQL
    data = sqlctx.sql(
        'select clientip, host, cast(csbytes as Double) as bytes \
        from sgos \
        where urischeme="ssl" and year=%s and month=%s and day=%s \
        or method="POST" and year=%s and month=%s and day=%s \
        group by clientip, host, cast(csbytes as Double) \
        order by cast(csbytes as Double) desc \
        limit %s' % (year, month, day, year, month, day, number)
    )

    # Save to JSON file in HDFS
    df.save('test.json', 'json', 'overwrite')
