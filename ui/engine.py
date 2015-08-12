from pyspark.sql import SQLContext
from pyspark import StorageLevel

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnalyticsEngine:
    """A security analytics engine
    """

    def __init__(self, sc, dataset_path):
        """Init the  engine given a Spark context and a dataset path
        """

        logger.info("Starting up the Analytics Engine: ")
        self.sc = sc

        # Load ratings data for later use
        logger.info("Loading SQLContext and data...")
        self.sqlctx = SQLContext(self.sc)
        self.vpnLogsDF = self.sqlctx.load(dataset_path)
        self.vpnLogsDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        self.sqlctx.registerDataFrameAsTable(self.vpnLogsDF, 'vpn')

    def getVPNLoginsByUser(self, username):
        loginsByUser = self.sqlctx.sql(
            "select `date`, time, remoteip, reason from vpn where user='%s' group by `date`, time, "
            "remoteip, reason" % (username)
        )
        jsonRDD = loginsByUser.toJSON()
        return jsonRDD
