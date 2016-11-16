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

    def __init__(self, yarn_cores, exec_cores, cores_max, instances, queue):
        '''
        Init function with default attributes
        :return:
        '''
        self.master = 'yarn'
        self.appName = 'BDSA 0.1-dev'
        self.spark_driver_cores = '8'
        self.spark_driver_maxResultSize = '512m'
        self.spark_driver_memory = '10g'
        self.spark_worker_memory = '12g'
        self.spark_executor_memory = '6g'
        self.spark_executor_cores = exec_cores
        self.spark_yarn_am_cores = yarn_cores
        self.spark_executor_instances = instances
        self.spark_cores_max = cores_max
        self.spark_network_timeout = '3000'
        self.spark_core_connection_ack_wait_timeout = '3000'
        self.spark_io_compression_codec = 'snappy'
        self.spark_serializer = 'org.apache.spark.serializer.KryoSerializer'
        self.spark_kryoserializer_buffer_max = '1024m'
        self.spark_sql_shuffle_partitions = '128'
        self.spark_sql_codegen = 'true'
        self.spark_sql_planner_externalSort = 'true'
        self.spark_scheduler_mode = "FAIR"
        self.spark_streaming_backpressure_enabled = 'true'
        self.spark_dynamicAllocation_enable = 'false'
        self.spark_shuffle_service_enabled = 'false'
        self.spark_scheduler_allocation_file = 'pool.xml'
        self.spark_yarn_queue = queue


    def setSparkConf(self):
        '''
        This function configures a Spark Context
        :return: sparkConf object
        '''
        conf = (SparkConf()
                #.setMaster(self.master)
                .setAppName(self.appName)
                .set("spark.driver.cores", self.spark_driver_cores)
                .set("spark.driver.maxResultSize", self.spark_driver_maxResultSize)
                .set("spark.driver.memory", self.spark_driver_memory)
                .set("spark.worker.memory", self.spark_worker_memory)
                .set("spark.executor.memory", self.spark_executor_memory)
                .set("spark.executor.cores", self.spark_executor_cores)
                .set("spark.cores.max", self.spark_cores_max)
                .set("spark.network.timeout", self.spark_network_timeout)
                .set("spark.core.connection.ack.wait.timeout", self.spark_core_connection_ack_wait_timeout)
                .set("spark.serializer", self.spark_serializer)
                .set("spark.kryoserializer.buffer.max", self.spark_kryoserializer_buffer_max)
                .set('spark.sql.shuffle.partitions', self.spark_sql_shuffle_partitions)
                .set('spark.sql.planner.externalSort', self.spark_sql_planner_externalSort)
                .set('spark.scheduler.mode', self.spark_scheduler_mode)
                #.set('spark.dynamicAllocation.enable', self.spark_dynamicAllocation_enable)
                #.set('spark.shuffle.service.enabled', self.spark_shuffle_service_enabled)
                .set("spark.scheduler.allocation.file", self.spark_scheduler_allocation_file)
                .set('spark.streaming.backpressure.enabled', self.spark_streaming_backpressure_enabled)
                #.set('spark.streaming.blockInterval', '0.2s')
                .set('spark.executor.instances', self.spark_executor_instances)
                .set('spark.yarn.am.cores', self.spark_yarn_am_cores)
                .set('spark.yarn.am.memory', '4g')
                .set('spark.yarn.executor.memoryOverhead', '1024')
                .set('spark.yarn.queue', self.spark_yarn_queue)
                )

        return conf

    def getConf(self):
        return SparkConf()
