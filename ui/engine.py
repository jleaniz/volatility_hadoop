from pyspark.sql import SQLContext
from pyspark import StorageLevel
import gviz_api

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnalyticsEngine:
    '''
    Security analytics engine class
    Contains all the analytics functions
    '''

    def __init__(self, sc, dataset_path):
        """
        Init the  engine given a Spark context and a dataset path
        """
        logger.info("Starting up the Analytics Engine: ")
        self.sc = sc

        # Load ratings data for later use
        logger.info("Creating Spark SQL context:")
        self.sqlctx = SQLContext(self.sc)

        # Load datasets as DataFrames and register temporary tables
        logger.info("Pre-loading some data for analysis:")
        self.vpnLogsDF = self.sqlctx.load(dataset_path)
        self.vpnLogsDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        self.sqlctx.registerDataFrameAsTable(self.vpnLogsDF, 'vpn')

    def getVPNLoginsByUserJSON(self, username):
        '''
        This function queries a DataFrame for logon/logoff data
        for a specified username

        :param username:
        :return:
        '''
        loginsByUser = self.sqlctx.sql(
            "select `date`, time, remoteip, reason from vpn where user='%s' group by `date`, time, "
            "remoteip, reason" % (username)
        )
        jsonRDD = loginsByUser.toJSON()
        return jsonRDD

    def getVPNLoginsByUserGoogle(self, username):
        '''
        This function queries a DataFrame for logon/logoff data
        for a specified username

        :param username:
        :return:
        '''
        loginsByUser = self.sqlctx.sql(
            "select remoteip, count(*) as hits from vpn where user='%s' group by remoteip" % (username)
        )
        entries = loginsByUser.collect()
        data = []
        description = {"remoteip": ("string", "Remote IP"),
                 "hits": ("number", "Hits")}

        for entry in entries:
            data.append([entry.remoteip, entry.hits])

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("remoteip", "hits"),
                           order_by="hits")

        return json