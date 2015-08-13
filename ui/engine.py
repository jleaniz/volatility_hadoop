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

        self.vpnLogsDF = self.sqlctx.load(
            "/user/cloudera/ciscovpn"
        )
        self.vpnLogsDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        self.sqlctx.registerDataFrameAsTable(self.vpnLogsDF, 'vpn')

        loginsByUser = self.sqlctx.sql(
            "select remoteip, count(*) as hits from vpn where user='%s' group by remoteip" % (username)
        )
        entries = loginsByUser.collect()
        data = []
        description = {"remoteip": ("string", "Remote IP"),
                       "hits": ("number", "Hits")}

        for entry in entries:
            data.append(
                {"remoteip": entry.remoteip, "hits": entry.hits}
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("remoteip", "hits"),
                                 order_by="hits")

        return json

    def getProxyUserMalwareHits(self, username, timerange):

        # Get the specified date
        (year, month, day) = timerange.split('-')

        # Load Spark SQL DataFrame
        self.proxyDF = self.sqlctx.load(
            "/user/cloudera/proxysg/year=%s/month=%s/day=%s" % (year, month, day)
        )
        # Persist the DataFrame - only on a huge cluster though..
        # self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        # Register DataFrame as a Spark SQL Table
        self.sqlctx.registerDataFrameAsTable(self.proxyDF, 'proxy')

        query = ("select clientip, username, host, port, path, query, count(*) as hits from proxy"
                 " where username='%s' and categories like '%s'"
                 " group by clientip, username, host, port, path, query"
                 " order by cast(hits as int) desc" % (username, '%Mal%'))
        # " limit 50" % (username, '%Internet%') )
        logger.info(query)

        # Query using Spark SQL
        userHistory = self.sqlctx.sql(query)
        userHistory.persist(StorageLevel.MEMORY_AND_DISK_SER)

        entries = userHistory.collect()
        data = []
        description = {
            "clientip": ("string", "Client IP"),
            "username": ("string", "Username"),
            "host": ("string", "Host"),
            "port": ("string", "Port"),
            "path": ("string", "Path"),
            "query": ("string", "Query"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            data.append(
                {
                    "clientip": entry.clientip,
                    "username": entry.username,
                    "host": entry.host,
                    "port": entry.port,
                    "path": entry.path,
                    "query": entry.query,
                    "hits": entry.hits,
                }
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("clientip", "username", "host", "port", "path", "query", "hits"),
                                 order_by="hits")

        return json

    def getTopTransfersProxy(self, timerange):
        '''
        :return:
        '''

        (year, month, day) = timerange.split('-')

        self.proxyDF = self.sqlctx.load(
            "/user/cloudera/proxysg/year=%s/month=%s/day=%s" % (year, month, day)
        )
        # self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        self.sqlctx.registerDataFrameAsTable(self.vpnLogsDF, 'proxy')

        loginsByUser = self.sqlctx.sql(
            'select clientip, host, cast(csbytes as Double) as bytes from proxy '
            'group by clientip, host, cast(csbytes as Double) order by cast(csbytes as Double) desc limit 10'
        )
        entries = loginsByUser.collect()
        data = []
        description = {"clientip": ("string", "Client IP"),
                       "host": ("string", "Destination host"),
                       "hits": ("number", "Hits")}

        for entry in entries:
            data.append(
                {"clientip": entry.clientip, "host": entry.host, "hits": entry.hits}
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("remoteip", "host", "hits"),
                                 order_by="hits")

        return json
