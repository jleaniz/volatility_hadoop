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
import urllib2

import lib.parser as parser
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def update_openphish(sContext):
    sqlCtx = SQLContext(sContext)
    data = urllib2.urlopen('https://openphish.com/feed.txt')
    results = []
    for line in data:
        results.append(line)

    rdd = sContext.parallelize(results)
    parsed_rdd = rdd.map(parser.Parser.parseOpenPhish)
    parsed_rdd.collect()
    df = parsed_rdd.toDF()
    df.save('reputation/openphish', 'parquet', 'overwrite')
