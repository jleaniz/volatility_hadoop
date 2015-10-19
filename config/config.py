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
from pyspark import SparkConf


class Config(object):
    '''
    Configuration class contains attributes used by the app
    and Spark
    '''

    def __init__(self):
        '''
        Init function with default attributes
        :return:
        '''
        self.master = 'spark://mtl-ah374.ubisoft.org:7077'
        self.appName = 'BDSA 0.1 alpha'
        self.spark_driver_cores = '8'
        self.spark_driver_maxResultSize = '4g'
        self.spark_driver_memory = '12g'
        self.spark_worker_memory = '1g'
        self.spark_executor_memory = '10g'
        self.spark_executor_cores = '8'
        self.spark_cores_max = '40'
        self.spark_akka_timeout = '3000'
        self.spark_network_timeout = '3000'
        self.spark_core_connection_ack_wait_timeout = '3000'
        self.spark_storage_memoryFraction = '0.6'
        # self.spark_metrics_conf = '/opt/cloudera/parcels/CDH/etc/spark/conf.dist/metrics.properties'
        # self.spark_default_parallelism = '120'
        self.spark_io_compression_codec = 'snappy'
        self.spark_serializer = 'org.apache.spark.serializer.KryoSerializer'
        self.spark_kryoserializer_buffer_max = '128m'
        # self.spark_rdd_compress = 'true'
        self.spark_sql_shuffle_partitions = '512'
        self.spark_sql_codegen = 'true'
        self.spark_sql_planner_externalSort = 'true'

    def setSparkConf(self):
        '''
        This function configures a Spark Context
        :return: sparkConf object
        '''
        conf = (SparkConf()
                .setMaster(self.master)
                .setAppName(self.appName)
                .set("spark.driver.cores", self.spark_driver_cores)
                .set("spark.driver.maxResultSize", self.spark_driver_maxResultSize)
                .set("spark.driver.memory", self.spark_driver_memory)
                .set("spark.worker.memory", self.spark_worker_memory)
                .set("spark.executor.memory", self.spark_executor_memory)
                .set("spark.executor.cores", self.spark_executor_cores)
                .set("spark.cores.max", self.spark_cores_max)
                .set("spark.akka.timeout", self.spark_akka_timeout)
                # .set("spark.metrics.conf", self.spark_metrics_conf)
                .set("spark.network.timeout", self.spark_network_timeout)
                .set("spark.core.connection.ack.wait.timeout", self.spark_core_connection_ack_wait_timeout)
                .set("spark.storage.memoryFraction", self.spark_storage_memoryFraction)
                # .set("spark.default.parallelism", self.spark_default_parallelism)
                .set("spark.serializer", self.spark_serializer)
                .set("spark.kryoserializer.buffer.max", self.spark_kryoserializer_buffer_max)
                # .set("spark.rdd.compress", self.spark_rdd_compress)
                .set('spark.sql.shuffle.partitions', self.spark_sql_shuffle_partitions))
        # .set('spark.sql.planner.externalSort', self.spark_sql_planner_externalSort)
        # .set('spark.sql.codegen', self.spark_sql_codegen)
        # .set("spark.io.compression.codec", self.spark_io_compression_codec))

        return conf

    def getConf(self):
        return SparkConf().getAll()