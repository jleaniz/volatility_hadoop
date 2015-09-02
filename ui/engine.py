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

from datetime import date, timedelta as td

from pyspark.sql import SQLContext
from pyspark import StorageLevel
from pyspark import SparkContext, SparkConf
from config import config as conf

from py4j.java_gateway import Py4JJavaError
import gviz_api
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
        '''
        logger.info("Loading Firewall data")
        self.firewallDF = self.sqlctx.load(
            "/user/cloudera/firewall/off"
        )
        self.sqlctx.registerDataFrameAsTable(self.firewallDF, 'firewall')

        logger.info("Loading Proxy data")
        # self.proxyDF = self.sqlctx.load(
        #    "/user/cloudera/proxysg"
        # )
        # self.sqlctx.registerDataFrameAsTable(self.proxyDF, 'proxysg')

        logger.info("Loading Bash data")
        self.bashDF = self.sqlctx.load(
            "/user/cloudera/bashlog"
        )
        self.sqlctx.registerDataFrameAsTable(self.bashDF, 'bashlog')
        '''
        '''
        Caching will make queries faster but for some reason
        it won't let you read certain partitions on a cached DF.
        Seems to read the entire DF every time, even if cached, it would be
        generally slower, unless querying a lot of data.
        '''
        # self.vpnLogsDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        # self.firewallDF.persist(StorageLevel.MEMORY_AND_DISK_SER)
        # self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER) # not enough capacity for this right now
        # self.bashDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

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

    def buildDateList(self, sdate, edate):

        (syear, smonth, sday) = sdate.split('-')
        (eyear, emonth, eday) = edate.split('-')
        _sdate = date(int(syear), int(smonth), int(sday))
        _edate = date(int(eyear), int(emonth), int(eday))
        delta = _edate - _sdate

        days = []
        for i in range(delta.days + 1):
            days.append(_sdate + td(days=i))

        return days

    def buildParquetFileList(self, table, sdate, edate):

        days = self.buildDateList(sdate, edate)

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

        # _parquetPaths = [x for x in parquetPaths if hdfs.exists(x)]
        _parquetPaths = [x for x in parquetPaths if os.path.exists('/mnt/hdfs' + x)]
        return _parquetPaths

    def getSearchResults(self, table, sdate, edate, query, num):
        # _parquetPaths = self.buildParquetFileList(table, sdate, edate)

        self.sqlctx.setConf("spark.sql.parquet.useDataSourceApi", "false")
        self.sqlctx.setConf("spark.sql.planner.externalSort", "true")
        self.sqlctx.setConf('spark.sql.parquet.mergeSchema', 'false')

        days = self.buildDateList(sdate, edate)

        if table == 'proxysg':
            tempDF = self.proxyDF
        elif table == 'ciscovpn':
            tempDF = self.vpnLogsDF
        elif table == 'firewall':
            tempDF = self.firewallDF

        for day in days:
            try:
                filteredDF = tempDF.filter(
                    'year=%s and month=%s and day=%s' % (day.year, str(day).split('-')[1], str(day).split('-')[2]))
                self.sqlctx.registerDataFrameAsTable(filteredDF, table)
                resultsDF = self.sqlctx.sql('%s limit %s' % (query, num))
                for result in resultsDF.toJSON().collect():
                    yield result
            except Py4JJavaError:
                pass

    def getCustomSearchResults(self, query):
        try:
            resultsDF = self.sqlctx.sql('%s' % (query))
            for result in resultsDF.toJSON().collect():
                yield result
        except Py4JJavaError:
            pass

    def bashKeywordSearch(self, keyword):

        query = ("select * from bashlog where username like '%s'" % (keyword))
        logger.info(query)

        # Query using Spark SQL
        keywordDF = self.sqlctx.sql(query)

        entries = keywordDF.collect()
        data = []
        description = {
            "logsrc": ("string", "Server"),
            "username": ("string", "Username"),
            "exec_as": ("string", "Sudo user"),
            "srcip": ("string", "Client IP"),
            "command": ("string", "Command")
        }

        for entry in entries:
            data.append(
                {
                    "logsrc": entry.logsrc,
                    "username": entry.username,
                    "exec_as": entry.exec_as,
                    "srcip": entry.srcip,
                    "command": entry.command,
                }
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("logsrc", "username", "exec_as", "srcip", "command"))

        return json

    def getFirewallPortStats(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('firewall', fromdate, todate)

        self.firewallDF = self.sqlctx.parquetFile(*_parquetPaths)
        self.sqlctx.registerDataFrameAsTable(self.firewallDF, 'firewall')

        PortStats = self.sqlctx.sql(
            'select dstport, count(*) as hits from firewall where action="DENY" '
            'group by dstport order by hits desc limit 10'
        )
        entries = PortStats.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "port": ("string", "Destination Port"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            dataChart.append( {"port": entry.dstport, "hits": entry.hits}  )

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        jsonChart = data_tableChart.ToJSon(
            columns_order=("port", "hits"),
            order_by="hits"
        )

        return jsonChart

    def identifyVPNUser(self, remoteip, date):
        '''

        :param username:
        :return:
        '''

        loginsByUser = self.sqlctx.sql(
            "select user from vpn where year=%s and month=%s and day=%s and remoteip='%s'" % (
                year, month, day, remoteip)
        )

        jsonRDD = loginsByUser.toJSON()

        return jsonRDD


def init_spark_context():
    # load spark context
    appConfig = conf.Config()
    # IMPORTANT: pass aditional Python modules to each worker
    sc = SparkContext(conf=appConfig.setSparkConf())

    return sc


sc = init_spark_context()
analytics_engine = AnalyticsEngine(sc)

def buildJSON(table, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(table, fromdate, todate, query, num)
    results = []

    results.append('{"%s": [\n' % (table))
    for item in jsonResult:
        results.append(item + ',\n')

    results.append('{}\n]}')

    return results


def buildJSONCustom(query):
    jsonResult = analytics_engine.getCustomSearchResults(query)
    results = []

    results.append('{"%s": [\n' % ("search"))
    for item in jsonResult:
        results.append(item + ',\n')

    results.append('{}\n]}')

    return results
