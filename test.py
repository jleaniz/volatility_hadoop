import utils
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
    volatility = utils.SparkVolatility('pslist')
    sqlContext = SQLContext(sc)

    df = sqlContext.load('Volatility/pslist')
    sqlContext.registerDataFrameAsTable(df, "pslist")
    pslist = sqlContext.sql("SELECT proclist FROM pslist WHERE image LIKE '" + "ds_fuzz_hidden_proc.img" + "'") 

    print pslist.collect()[0][0]
    
    