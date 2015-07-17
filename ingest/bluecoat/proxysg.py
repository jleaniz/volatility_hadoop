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
import os

import bdsa.lib.parser as parser
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def save_access_log(sContext, path):
    sqlCtx = SQLContext(sContext)
    sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
    local_path = '/mnt/hdfs/' + path
    years = os.listdir(local_path)
    myParser = parser.Parser('bluecoat')
    for year in years:
        months = os.listdir(local_path + '/' + year)
        for month in months:
            days = os.listdir(local_path + '/' + year + '/' + month)
            for day in days:
                if os.listdir(local_path + '/' + year + '/' + month + '/' + day):
                    access_log_rdd = sContext.textFile(path + '/' + year + '/'
                                                       + month + '/' + day + '/*').repartition(
                        sContext.defaultParallelism)
                    parsed_rdd = access_log_rdd.mapPartitions(myParser.parseBCAccessLog)
                    df = parsed_rdd.toDF()
                    df.save('/user/cloudera/proxy/accesslog/p_year=2015/p_month=' + str(int(month))
                            + '/p_day=' + str(int(day)), 'parquet', 'append')
