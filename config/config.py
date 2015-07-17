from pyspark import SparkConf


class Config:
    def __init__(self):
        self.master = 'spark://mtl-srm-cdh01.ubisoft.org:7077'
        self.appName = 'BDSA 0.1 alpha'
        self.spark_driver_cores = '1'
        self.spark_driver_maxResultSize = '200m'
        self.spark_driver_memory = '512m'
        self.spark_worker_memory = '512m'
        self.spark_executor_memory = '512m'
        self.spark_executor_cores = '4'
        self.spark_cores_max = '20'
        self.spark_akka_timeout = '3000'
        self.spark_network_timeout = '3000'
        self.spark_core_connection_ack_wait_timeout = '3000'
        self.spark_storage_memoryFraction = '0.6'
        self.spark_default_parallelism = '60'

    def setSparkConf(self):
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
                .set("spark.network.timeout", self.spark_network_timeout)
                .set("spark.core.connection.ack.wait.timeout", self.spark_core_connection_ack_wait_timeout)
                .set("spark.storage.memoryFraction", self.spark_storage_memoryFraction)
                .set("spark.default.parallelism", self.spark_default_parallelism))

        return conf
