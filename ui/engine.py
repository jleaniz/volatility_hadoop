from datetime import date, timedelta as td

from pyspark.sql import SQLContext
from pyspark import StorageLevel
from py4j.java_gateway import Py4JJavaError
import gviz_api
import lib.hdfs as hdfs
import os

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnalyticsEngine:
    '''
    Security analytics engine class
    Contains all the analytics functions
    '''

    def __init__(self, sc):
        """
        Init the  engine given a Spark context and a dataset path
        """
        logger.info("Starting up the Analytics Engine: ")
        self.sc = sc

        # Load ratings data for later use
        logger.info("Creating Spark SQL context:")
        self.sqlctx = SQLContext(self.sc)

        # pre-laod some data
        logger.info("Loading Cisco VPN data")
        self.vpnLogsDF = self.sqlctx.load(
            "/user/cloudera/ciscovpn"
        )
        self.sqlctx.registerDataFrameAsTable(self.vpnLogsDF, 'vpn')

        logger.info("Loading Firewall data")
        self.firewallDF = self.sqlctx.load(
            "/user/cloudera/firewall/off"
        )
        self.sqlctx.registerDataFrameAsTable(self.firewallDF, 'firewall')

        logger.info("Loading Proxy data")
        self.proxyDF = self.sqlctx.load(
            "/user/cloudera/proxysg"
        )
        self.sqlctx.registerDataFrameAsTable(self.proxyDF, 'proxysg')

        self.vpnLogsDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        self.firewallDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)


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
            data.append(
                {"remoteip": entry.remoteip, "hits": entry.hits}
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("remoteip", "hits"),
                                 order_by="hits")

        return json

    def getProxyUserMalwareHits(self, username, fromdate, todate):

        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)

        self.proxyDF = self.sqlctx.parquetFile(*_parquetPaths)
        # Register DataFrame as a Spark SQL Table
        self.sqlctx.registerDataFrameAsTable(self.proxyDF, 'proxysg')

        query = ("select clientip, username, host, port, path, query, count(*) as hits from proxysg"
                 " where username like '%s' and categories like '%s'"
                 " group by clientip, username, host, port, path, query"
                 " order by cast(hits as int) desc" % (username, '%Mal%'))
        # " limit 50" % (username, '%Internet%') )
        logger.info(query)

        # Query using Spark SQL
        userHistory = self.sqlctx.sql(query)

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

    def getTopTransfersProxy(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)

        self.proxyDF = self.sqlctx.parquetFile(*_parquetPaths)
        self.sqlctx.registerDataFrameAsTable(self.proxyDF, 'proxysg')

        topTransfers = self.sqlctx.sql(
            'select clientip, host, cast(csbytes as Double) as bytes from proxysg '
            'group by clientip, host, cast(csbytes as Double) order by bytes desc limit 10'
        )
        entries = topTransfers.collect()

        # Build json object for the table
        data = []
        descriptionTable = {
            "host": ("string", "Destination"),
            "bytes": ("number", "Bytes"),
            "clientip": ("string", "Client IP")
        }

        for entry in entries:
            data.append(
                {"clientip": entry.clientip, "bytes": entry.bytes, "host": entry.host}
            )

        data_table = gviz_api.DataTable(descriptionTable)
        data_table.LoadData(data)
        # Creating a JSon string
        jsonTable = data_table.ToJSon(
            columns_order=("clientip", "host", "bytes"),
            order_by="bytes"
        )

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "clientip": ("string", "Client IP"),
            "bytes": ("number", "Bytes")
        }

        for entry in entries:
            dataChart.append(
                {"clientip": entry.clientip, "bytes": entry.bytes}
            )

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        jsonChart = data_table.ToJSon(
            columns_order=("clientip", "bytes"),
            order_by="bytes"
        )

        return (jsonTable, jsonChart)

    '''
    def ifExistsSlow(self, item):
        try:
            self.tableDF = self.sqlctx.parquetFile(item)
            self.tableDF = None
            return True
        except Py4JJavaError:
            logger.info('unable to load file %s. skipping' %(item))
            return False
    '''

    def buildParquetFileList(self, table, sdate, edate):

        (syear, smonth, sday) = sdate.split('-')
        (eyear, emonth, eday) = edate.split('-')
        _sdate = date(int(syear), int(smonth), int(sday))
        _edate = date(int(eyear), int(emonth), int(eday))
        delta = _edate - _sdate

        days = []
        for i in range(delta.days + 1):
            days.append(_sdate + td(days=i))

        parquetPaths = []
        for day in days:
            if table == 'firewall':
                parquetPaths.append(
                    '/user/cloudera/%s/off/year=%s/month=%s/day=%s' % (
                        table, day.year, str(day).split('-')[1], str(day).split('-')[2])
                )
            else:
                parquetPaths.append(
                    '/user/cloudera/%s/year=%s/month=%s/day=%s' % (
                        table, day.year, str(day).split('-')[1], str(day).split('-')[2])
                )

        #_parquetPaths = [x for x in parquetPaths if hdfs.exists(x)]
        _parquetPaths = [x for x in parquetPaths if os.path.exists('/mnt/hdfs'+x)]
        return _parquetPaths

    def getSearchResults(self, table, sdate, edate, query, num):

        _parquetPaths = self.buildParquetFileList(table, sdate, edate)

        self.sqlctx.setConf("spark.sql.parquet.useDataSourceApi", "false")
        self.sqlctx.setConf("spark.sql.planner.externalSort", "true")
        self.sqlctx.setConf('spark.sql.parquet.mergeSchema', 'false')

        # spark 1.3
        self.tempDF = self.sqlctx.parquetFile(*_parquetPaths)
        self.sqlctx.registerDataFrameAsTable(self.tempDF, table)

        # spark 1.4+ compatible
        #self.tableDF = self.sqlctx.read.parquet(*_parquetPaths)
        #self.tableDF.registerTempTable(table)

        try:
            results = self.sqlctx.sql('%s limit %s' % (query, num))
            #for json in results.toJSON().collect():
            #    yield json
            return results.toJSON().collect()
        except Py4JJavaError:
            pass


    def identifyVPNUser(self, remoteip, date):
        '''

        :param username:
        :return:
        '''

        loginsByUser = self.sqlctx.sql(
            "select user from vpn where year=%s and month=%s and day=%s and remoteip='%s'" %(year, month, day, remoteip)
        )

        jsonRDD = loginsByUser.toJSON()

        return jsonRDD