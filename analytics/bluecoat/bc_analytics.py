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


def getClientsByTransferP(sc, parquetFiles, number, month):
    '''
    Get a list of client ips ordered by bytes transfered
    :param sc: SparkContext
    :param number: limit results to 'number'
    :return: DataFrame
    '''

    # Creat Spark SQL context
    sqlctx = SQLContext(sc)
    # Load files into a DataFrame
    df = sqlctx.parquetFile(parquetFiles)
    # Register temporary in-memory table
    sqlctx.registerDataFrameAsTable(df, 'sgos')

    # Query using Spark SQL
    data = sqlctx.sql(
        'select p_day, clientip, host, cast(csbytes as bigint) as bytes \
        from sgos_accesslog \
        where urischeme="ssl" and p_month=%s or method="POST" and p_month=%s \
        group by p_day, clientip, host, cast(csbytes as bigint) \
        order by cast(csbytes as bigint) desc \
        limit %s' % (month, month, number)
    )

    # Save to JSON file in HDFS
    df.save('test.json', 'json', 'overwrite')

    return data
