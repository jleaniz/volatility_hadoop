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
from pyspark.sql import SparkSession, Row
from pyspark.sql.functions import asc, desc, concat, lit, col
from pyspark import StorageLevel
from pyspark import SparkContext, SparkConf
from pyspark.mllib.clustering import KMeans
from pyspark.mllib.feature import Word2Vec
from pyspark.ml.feature import Word2Vec
from pyspark.ml.clustering import KMeans, KMeansModel
from pyspark.sql.utils import AnalysisException
from config import config as conf
#from py4j.java_gateway import Py4JJavaError
import gviz_api
import os
import GeoIP
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnalyticsEngine(object):
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

        # Create a SparkSession
        logger.info("Creating Spark SQL context:")
        self.session = SparkSession \
            .builder \
            .appName("BDSA ui v0.1") \
            .getOrCreate()

        # default resource pool
        self.sc.setLocalProperty("spark.scheduler.pool", "default")

    def get_sc(self):
        return self.sc

    def getVPNLoginsByUserJSON(self, username):
        '''
        This function queries a DataFrame for logon/logoff data
        for a specified username

        :param username:
        :return:
        '''

        loginsByUser = self.session.sql(
            "select `date`, time, remoteip, reason from ciscovpn where user='%s' group by `date`, time, "
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

        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        loginsByUser = self.session.sql(
            "select remoteip, count(*) as hits from ciscovpn where user='%s' group by remoteip" % (username)
        )
        entries = loginsByUser.collect()
        data = []

        description = [("remoteip",'string', "Remote IP"),
               ("activity","string", "Activity",{'role':'annotation'}),
               ("hits","number", "Hits")]

        for entry in entries:
            if entry.hits < 10:
                activity = 'Unusual'
            else:
                activity = 'Normal'
            data.append(
                [entry.remoteip, activity, entry.hits ]
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("remoteip", "hits", "activity"),
                                 order_by="hits")

        return json


    def getVPNUnusualActivity(self):
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        adlocation = self.session.read.parquet('ad.csv').filter('c not like ""')
        adlocation.cache()

        vpn = self.session.read.parquet('/data/srm/dbs/dw_srm.db/vpn/ciscovpn')
        vpn.cache()

        def func(x):
            gi = GeoIP.open("GeoIP.dat",GeoIP.GEOIP_MEMORY_CACHE)
            cc = gi.country_code_by_addr(x.remoteip)
            return Row(bytesrcv=x.bytesrcv, bytesxmt=x.bytesxmt, duration=x.duration, localip=x.localip, reason=x.reason,
                       remoteip=x.remoteip, source=x.source, time=x.time, user=x.user, date=x.date, remoteipcc=cc)

        vpnDF = vpn.map(func).toDF()
        joinDF = vpnDF.join(adlocation, vpnDF.user == adlocation.EmailAddress)
        joinDF.cache()

        fromOtherLocations = joinDF.filter("remoteipcc <> c")
        groupDF = fromOtherLocations.groupBy(fromOtherLocations.user, fromOtherLocations.remoteip, fromOtherLocations.remoteipcc, fromOtherLocations.c)\
            .count()\
            .orderBy(desc('count'))
        entries = groupDF.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "user": ("string", "User"),
            "c": ("string", "Office"),
            "remoteip": ("string", "Remote IP"),
            "remoteipcc": ("string", "Remote IP CC"),
            "count": ("number", "Count")
        }

        for entry in entries:
            dataChart.append({
                "user": entry.user,
                "c": entry.c,
                "remoteip": entry.remoteip,
                "remoteipcc": entry.remoteipcc,
                "count": int(entry[4])})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        vpn_logins = data_tableChart.ToJSon(
            columns_order=("user", "c", "remoteip","remoteipcc","count"),
            order_by="count"
        )
        return vpn_logins



    def getProxyUserMalwareHits(self, username, fromdate, todate):

        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        # Register DataFrame as a Spark SQL Table
        self.proxyDF.createOrReplaceTempView('proxysg')
        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER) # not enough capacity for this right now

        query = ("select clientip, username, host, port, path, query, count(*) as hits from proxysg"
                 " where username like '%s' and categories like '%s'"
                 " group by clientip, username, host, port, path, query"
                 " order by cast(hits as int) desc" % (username, '%Mal%'))
        # " limit 50" % (username, '%Internet%') )
        logger.info(query)

        # Query using Spark SQL
        userHistory = self.session.sql(query)

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
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        self.proxyDF.createOrReplaceTempView('proxysg')

        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        topTransfers = self.session.sql(
            'select clientip, host, cast(csbytes as Double) as bytes from proxysg group by clientip, host, cast(csbytes as Double) order by bytes desc limit 10'
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

    def getLeastCommonUserAgents(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        self.proxyDF.createOrReplaceTempView('proxysg')

        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        uncommonAgents = self.session.sql(
            'select agent, count(*) as hits from proxysg '
            'group by agent order by hits asc limit 500'
        )
        entries = uncommonAgents.collect()

        # Build json object for the table
        data = []
        descriptionTable = {
            "agent": ("string", "User-Agent"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            data.append({"agent": entry.agent, "hits": entry.hits})

        data_table = gviz_api.DataTable(descriptionTable)
        data_table.LoadData(data)
        # Creating a JSon string
        jsonTable = data_table.ToJSon(columns_order=("agent", "hits"), order_by="hits")

        return jsonTable

    def getMostVisitedDomains(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        self.proxyDF.createOrReplaceTempView('proxysg')
        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        visitedDomains = self.session.sql(
            'select host, count(*) as hits from proxysg '
            'group by host order by hits desc limit 15'
        )
        entries = visitedDomains.collect()

        # Build json object for the table
        data = []
        descriptionTable = {
            "host": ("string", "Domain"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            data.append({"host": entry.host, "hits": entry.hits})

        data_table = gviz_api.DataTable(descriptionTable)
        data_table.LoadData(data)
        # Creating a JSon string
        jsonTable = data_table.ToJSon(columns_order=("host", "hits"), order_by="hits")

        return jsonTable

    def getMostVisitedMalwareDomains(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        self.proxyDF.createOrReplaceTempView('proxysg')

        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        malwareDomains = self.session.sql(
            'select host, count(*) as hits from proxysg where categories like "%Mal%" '
            'group by host order by hits desc limit 15'
        )
        entries = malwareDomains.collect()

        # Build json object for the table
        data = []
        descriptionTable = {
            "host": ("string", "Domain"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            data.append({"host": entry.host, "hits": entry.hits})

        data_table = gviz_api.DataTable(descriptionTable)
        data_table.LoadData(data)
        # Creating a JSon string
        jsonTable = data_table.ToJSon(columns_order=("host", "hits"), order_by="hits")

        return jsonTable

    def getOutdatedClients(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        self.proxyDF.createOrReplaceTempView('proxysg')

        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        ooutdatesClients = self.session.sql(
            'select clientip, agent from proxysg where agent like "%NT 5.1%" or agent like "%NT\\ 5.1%" group by clientip, agent'
        )
        entries = ooutdatesClients.collect()

        # Build json object for the table
        data = []
        descriptionTable = {
            "clientip": ("string", "Client"),
            "agent": ("string", "User-Agent")
        }

        for entry in entries:
            data.append({"clientip": entry.clientip, "agent": entry.agent})

        data_table = gviz_api.DataTable(descriptionTable)
        data_table.LoadData(data)
        # Creating a JSon string
        jsonTable = data_table.ToJSon(columns_order=("clientip", "agent"))

        return jsonTable

    def getProxyIntelHits(self, fromdate, todate):
        '''
        :return:
        '''
        _parquetPaths = self.buildParquetFileList('proxysg', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.proxyDF = self.session.read.parquet(*_parquetPaths)
        self.proxyDF.createOrReplaceTempView('proxysg')

        #self.proxyDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        sgotx = self.session.sql('select proxysg.host from proxysg join otx on otx.ip=proxysg.host')
        sgc2 = self.session.sql('select proxysg.host from proxysg join c2 on c2.host=proxysg.host')
        sgall = sgotx.unionAll(sgc2)

        # This breaks the Kryo serializer - unknown class
        entries = sgall.groupBy(sgall.host).count().orderBy(desc('count')).limit(20).collect()

        # Build json object for the table
        data = []
        descriptionTable = {
            "host": ("string", "Malware host"),
            "count": ("number", "Hits")
        }

        for entry in entries:
            data.append({"host": entry.host, "count": int(entry[1])})

        data_table = gviz_api.DataTable(descriptionTable)
        data_table.LoadData(data)
        # Creating a JSon string
        jsonTable = data_table.ToJSon(columns_order=("host", "count"), order_by="count")

        return jsonTable

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
        '''
        TODO : Return a DataFrame after checking all paths
        :param table:
        :param sdate:
        :param edate:
        :return:
        '''
        days = self.buildDateList(sdate, edate)

        parquetPaths = []
        for day in days:
            if table == 'fw':
                parquetPaths.append(
                    '/data/srm/dbs/dw_srm.db/fw/date=%s%s%s' % (
                        day.year, str(day).split('-')[1], str(day).split('-')[2])
                )
            else:
                parquetPaths.append(
                    '/data/srm/dbs/dw_srm.db/%s/date=%s-%s-%s' % (
                        table, day.year, str(day).split('-')[1], str(day).split('-')[2])
                )

        #_parquetPaths = [x for x in parquetPaths if os.path.exists('/mnt/hdfs' + x)]
        _parquetPaths = [x for x in parquetPaths]

        return _parquetPaths

    def getSearchResults(self, tables, sdate, edate, query, num):
        #days = self.buildDateList(sdate, edate)
        try:
            if 'proxysg' in tables:
                _parquetPaths = self.buildParquetFileList('proxysg', sdate, edate)
                self.proxyDF = self.session.read.parquet(*_parquetPaths)
                self.proxyDF.createOrReplaceTempView('proxysg')

            if 'ciscovpn' in tables:
                _parquetPaths = self.buildParquetFileList('ciscovpn', sdate, edate)
                self.vpnLogsDF = self.session.read.parquet(*_parquetPaths)
                self.vpnLogsDF.createOrReplaceTempView('ciscovpn')

            if 'firewall' in tables:
                logger.info('Re-loading dataframe fw')
                _parquetPaths = self.buildParquetFileList('fw', sdate, edate)
                self.fwDF = self.session.read.parquet(*_parquetPaths)
                self.fwDF.createOrReplaceTempView('fw')

            if 'bashlog' in tables:
                logger.info('Re-loading dataframe bashlog')
                _parquetPaths = self.buildParquetFileList('bashlog', sdate, edate)
                self.bashDF = self.session.read.parquet(*_parquetPaths)
                self.bashDF.createOrReplaceTempView('bashlog')

            if 'sccm_vuln' in tables:
                if not self.sccmDF:
                    self.session.read.parquet('/user/jleaniz/sccm/df_sys_dsA1')

        except AttributeError as e:
            logger.info('AttributeError' + str(e))
            pass

        try:
            self.sc.setLocalProperty("spark.scheduler.pool", "search")

            resultsDF = self.session.sql('%s limit %s' % (query, num))
            for result in resultsDF.toJSON().collect():
                yield result
        except Exception as e:
            logger.info('Py4JavaError: ' + str(e))
            pass

    def getCustomSearchResults(self, query):
        try:
            resultsDF = self.session.sql('%s' % (query))
            for result in resultsDF.toJSON().collect():
                yield result
        except:
            pass

    def bashKeywordSearch(self, keyword, fromdate, todate):
        _parquetPaths = self.buildParquetFileList('bashlog', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.bashDF = self.session.read.parquet(*_parquetPaths)
        self.bashDF.createOrReplaceTempView('bashlog')

        query = ("select * from bashlog where command like '%s'" % (keyword))
        logger.info(query)

        # Query using Spark SQL
        keywordDF = self.session.sql(query)

        entries = keywordDF.collect()
        data = []
        description = {
            "source": ("string", "Server"),
            "username": ("string", "Username"),
            "exec_as": ("string", "Sudo user"),
            "srcip": ("string", "Client IP"),
            "command": ("string", "Command")
        }

        for entry in entries:
            data.append(
                {
                    "source": entry.source,
                    "username": entry.username,
                    "exec_as": entry.exec_as,
                    "srcip": entry.srcip,
                    "command": entry.command,
                }
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("source", "username", "exec_as", "srcip", "command"))

        return json

    def bashUserActivity(self, keyword, fromdate, todate):
        _parquetPaths = self.buildParquetFileList('bashlog', fromdate, todate)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        self.bashDF = self.session.read.parquet(*_parquetPaths)
        self.bashDF.createOrReplaceTempView('bashlog')

        query = ( "select * from bashlog where username like  ' %s' " % (keyword) )
        logger.info(query)

        # Query using Spark SQL
        keywordDF = self.session.sql(query)

        entries = keywordDF.collect()
        data = []
        description = {
            "source": ("string", "Server"),
            "username": ("string", "Username"),
            "exec_as": ("string", "Sudo user"),
            "srcip": ("string", "Client IP"),
            "command": ("string", "Command")
        }

        for entry in entries:
            data.append(
                {
                    "source": entry.source,
                    "username": entry.username,
                    "exec_as": entry.exec_as,
                    "srcip": entry.srcip,
                    "command": entry.command,
                }
            )

        data_table = gviz_api.DataTable(description)
        data_table.LoadData(data)
        # Creating a JSon string
        json = data_table.ToJSon(columns_order=("source", "username", "exec_as", "srcip", "command"))

        return json

    def getfwPortStats(self, fromdate, todate):
        try:
            if self.fwDF:
                logger.info("Already loaded this DataFrame")
                pass
        except:
            logger.info("Loading new DataFrame")
            _parquetPaths = self.buildParquetFileList('fw', fromdate, todate)
            self.fwDF = self.session.read.parquet(*_parquetPaths)
            self.fwDF.createOrReplaceTempView('fw')
            #self.fwDF.persist(StorageLevel.MEMORY_ONLY_SER)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        PortStats = self.session.sql(
            'select dstport, proto, count(*) as hits from fw where action="DENY" group by dstport, proto order by hits desc limit 10'
        )
        entries = PortStats.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "port": ("string", "Destination Port/Proto"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            dataChart.append({"port": str(entry.dstport) + '/' + entry.proto, "hits": entry.hits})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        fw_port_stats = data_tableChart.ToJSon(
            columns_order=("port", "hits"),
            order_by="hits"
        )

        return fw_port_stats

    def getfwIPStats(self, fromdate, todate):

        _parquetPaths = self.buildParquetFileList('fw', fromdate, todate)
        self.fwDF = self.session.read.parquet(*_parquetPaths)
        self.fwDF.createOrReplaceTempView('fw')
        #self.fwDF.persist(StorageLevel.MEMORY_ONLY_SER)

        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        dstIPStats = self.session.sql(
            'select dstip, dstport, proto, count(*) as hits from fw where action="DENY" group by dstip, dstport, proto order by hits desc limit 10'
        )
        entries = dstIPStats.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "dstip": ("string", "Destination IP/Port/Proto"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            dataChart.append({"dstip": entry.dstip + ' ' + str(entry.dstport) + '/' + entry.proto, "hits": entry.hits})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        fw_dstip_stats = data_tableChart.ToJSon(
            columns_order=("dstip", "hits"),
            order_by="hits"
        )

        srcIPStats = self.session.sql(
            'select srcip, dstport, proto, count(*) as hits from fw where action="DENY" '
            'group by srcip, dstport, proto order by hits desc limit 10'
        )
        entries = srcIPStats.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "srcip": ("string", "Source IP/Port/Proto"),
            "hits": ("number", "Hits")
        }

        for entry in entries:
            dataChart.append({"srcip": entry.srcip + ' ' + str(entry.dstport) + '/' + entry.proto, "hits": entry.hits})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        fw_srcip_stats = data_tableChart.ToJSon(
            columns_order=("srcip", "hits"),
            order_by="hits"
        )

        return (fw_srcip_stats, fw_dstip_stats)


    def getfwMalwareConns(self, fromdate, todate):

        _parquetPaths = self.buildParquetFileList('fw', fromdate, todate)
        self.fwDF = self.session.read.parquet(*_parquetPaths)
        self.fwDF.createOrReplaceTempView('fw')
        #self.fwDF.persist(StorageLevel.MEMORY_AND_DISK_SER)

        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        fwotx = self.session.sql('select fw.dstip from fw join otx on otx.ip=fw.dstip')
        fwc2 = self.session.sql('select fw.dstip from fw join c2 on c2.host=fw.dstip')
        fwall = fwotx.unionAll(fwc2)

        groupcnt = fwall.groupBy(fwall.dstip).count().orderBy(desc('count'))

        entries = groupcnt.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "dstip": ("string", "Malicious host"),
            "count": ("number", "Hits")
        }

        for entry in entries:
            dataChart.append({"dstip": entry.dstip, "count": entry[1]})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        fw_mal_conns = data_tableChart.ToJSon(
            columns_order=("dstip", "count"),
            order_by="count"
        )

        return fw_mal_conns


    def getfwTopTalkers(self, fromdate, todate):

        _parquetPaths = self.buildParquetFileList('fw', fromdate, todate)
        self.fwDF = self.session.read.parquet(*_parquetPaths)
        self.fwDF.createOrReplaceTempView('fw')
        #self.fwDF.persist(StorageLevel.MEMORY_ONLY_SER)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        srcdstips = self.session.sql('select srcip,dstip from fw where action="DENY"')

        groupcnt = srcdstips.groupBy(srcdstips.srcip,srcdstips.dstip).count().orderBy(desc('count')).limit(25)
        entries = groupcnt.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "srcip": ("string", "Source IP"),
            "dstip": ("string", "Destination IP"),
            "count": ("number", "Hits")
        }

        for entry in entries:
            dataChart.append({"srcip": entry.srcip ,"dstip": entry.dstip, "count": entry[2]})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        fw_top_talkers = data_tableChart.ToJSon(
            columns_order=("srcip", "dstip", "count"),
            order_by="count"
        )

        return fw_top_talkers


    def getfwStats(self, fromdate, todate):

        _parquetPaths = self.buildParquetFileList('fw', fromdate, todate)
        self.fwDF = self.session.read.parquet(*_parquetPaths)
        self.fwDF.createOrReplaceTempView('fw')
        #self.fwDF.persist(StorageLevel.MEMORY_ONLY_SER)

        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        fw_port_stats = self.getfwPortStats(fromdate, todate)
        (fw_srcip_stats, fw_dstip_stats) = self.getfwIPStats(fromdate, todate)

        return (fw_port_stats, fw_dstip_stats, fw_srcip_stats)

    def identifyVPNUser(self, remoteip, date):
        '''

        :param username:
        :return:
        '''
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        (year, month, day) = date.split('-')
        loginsByUser = self.session.sql(
            "select user from vpn where year=%s and month=%s and day=%s and remoteip='%s'" % (
                year, month, day, remoteip)
        )

        jsonRDD = loginsByUser.toJSON()

        return jsonRDD

    def GenerateDashboard(self):
        '''
        By default this function generates the dashboard
        using data from the last 30 days
        :return:
        '''
        today = date.today()
        start = today - td(today.day + 40)
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")
        str_today = today.strftime('%Y-%m-%d')
        str_start = start.strftime('%Y-%m-%d')
        (fw_port_stats, fw_dstip_stats, fw_srcip_stats) = self.getfwStats(str_start, str_today)
        # proxy_top_transfers = self.getTopTransfersProxy(str_start, str_today)

        return (fw_port_stats, fw_dstip_stats, fw_srcip_stats)

    def clearcache(self):
        try:
            self.fwDF.unpersist()
            self.proxyDF.unpersist()
            logger.info("Cache cleared")
            return True
        except:
            logger.info("Cache not cleared")
            return False

    def canceljobs(self):
        try:
            self.sc.cancelAllJobs()
            logger.info("Jobs cancelled")
            return True
        except:
            logger.info("Unable to cancel jobs")
            return False

    def FSTimelineStats(self, csv_path):
        '''
        :param csv_path:
        :return:
        '''
        # Load CSV files into a Spark DataFrame
        df = self.session.load(source="com.databricks.spark.csv", header="true", path=csv_path)
        # Register the DataFrame as a Spark SQL table called 'tl' so we can run queries using SQL syntax
        self.session.registerDataFrameAsTable(df, 'tl')
        # Cache the table in memory for faster lookups
        self.session.cacheTable('tl')

        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        # Create a df that contains deleted files
        deletedFilesDF = self.session.sql("SELECT `date`, short FROM tl WHERE short LIKE '%DELETED%'")
        self.session.registerDataFrameAsTable(deletedFilesDF, 'deleted')
        # Create a list with dates and number of deleted files per day
        deletedFilesDateList = self.session.sql(
            "SELECT `date`, count(*) as hits FROM deleted group by `date` order by hits desc limit 15").collect()

        zipFiles = int(self.session.sql("SELECT count(*) as hits FROM tl WHERE short LIKE '%zip'").collect()[0].hits)
        pdfFiles = int(self.session.sql("SELECT count(*) as hits FROM tl WHERE short LIKE '%pdf'").collect()[0].hits)
        exeFiles = int(self.session.sql("SELECT count(*) as hits FROM tl WHERE short LIKE '%exe'").collect()[0].hits)

        dataChart = []
        descriptionChart = {
            "date": ("string", "Date"),
            "hits": ("number", "Deleted files")
        }

        for row in deletedFilesDateList:
            dataChart.append({"date": row.date, "hits": row.hits})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        deleted_files_byDate = data_tableChart.ToJSon(
            columns_order=("date", "hits"),
            order_by="hits"
        )
        # webhist = self.session.sql("select `date`, short from tl where source='WEBHIST' limit 100 ").collect()

        dataChart = []
        descriptionChart = {
            "filetype": ("string", "File Type"),
            "hits": ("number", "Entries")
        }

        dataChart.append({"filetype": 'zip', "hits": zipFiles})
        dataChart.append({"filetype": 'pdf', "hits": pdfFiles})
        dataChart.append({"filetype": 'exe', "hits": exeFiles})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        filetype_count = data_tableChart.ToJSon(
            columns_order=("filetype", "hits"),
            order_by="hits"
        )

        return deleted_files_byDate, filetype_count


    def initializeModels(self):
        try:
            if self.kmeansDF:
                logger.info("Already loaded this DataFrame")
                pass
        except AttributeError:
            self.kmeansDF = None

        commandsDF = self.bashDF.map(lambda row: Row(date=row.date,
                                                     source=row.source,
                                                     username=row.username,
                                                     exec_as=row.exec_as,
                                                     srcip=row.srcip,
                                                     command=row.command.split(" "))).toDF()
        commandsDF.cache()

        word2Vec = Word2Vec(vectorSize=100, minCount=1, inputCol="command", outputCol="features")
        w2model = word2Vec.fit(commandsDF)
        resultDF = w2model.transform(commandsDF)
        resultDF.cache()

        kmeans = KMeans(k=650, seed=42, featuresCol="features", predictionCol="prediction", maxIter=10, initSteps=3)
        kmodel = kmeans.fit(resultDF)

        kmeansDF = kmodel.transform(resultDF)
        kmeansDF.cache()
        kmeansDF.coalesce(1).write.parquet('/user/jleaniz/ml/kmeans', mode='append')

        outliers = kmeansDF.groupBy("prediction").count().filter('count < 10').withColumnRenamed("prediction", "cluster")

        self.outlierCmds = outliers.join(kmeansDF, kmeansDF.prediction == outliers.cluster)


    def pm_dashboard(self):
        try:
            self.sccmDF = self.session.read.parquet('/user/jleaniz/sccm/df_sys_dsA1')
        except AnalysisException as e:
            logger.warning((e.__str__().split(' ')[-1]))
            logger.warning(e)
            logger.warning(e.args)
            logger.warning(e.message)
            return

        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        self.sccmDF = self.sccmDF.filter('crit_X_cat="High"')
        df_most_vuln = self.sccmDF.select('DisplayName0','Version0').groupBy('DisplayName0','Version0').count().orderBy(desc('count')).limit(10)\
            .select(concat(col("DisplayName0"),lit(" "),col("Version0")),"count").withColumnRenamed("concat(DisplayName0, ,Version0)", "software").collect()
        df_ncsa_most_vuln = self.sccmDF.filter('Region_X="NCSA" and Zone_X="Corp"').select('DisplayName0','Version0').groupBy('DisplayName0','Version0').count().orderBy(desc('count')).limit(10)\
            .select(concat(col("DisplayName0"),lit(" "),col("Version0")),"count").withColumnRenamed("concat(DisplayName0, ,Version0)", "software").collect()
        df_emea_most_vuln = self.sccmDF.filter('Region_X="EMEA" and Zone_X="Corp"').select('DisplayName0','Version0').groupBy('DisplayName0','Version0').count().orderBy(desc('count')).limit(10)\
            .select(concat(col("DisplayName0"),lit(" "),col("Version0")),"count").withColumnRenamed("concat(DisplayName0, ,Version0)", "software").collect()
        df_apac_most_vuln = self.sccmDF.filter('Region_X="APAC" and Zone_X="Corp"').select('DisplayName0','Version0').groupBy('DisplayName0','Version0').count().orderBy(desc('count')).limit(10)\
        .select(concat(col("DisplayName0"),lit(" "),col("Version0")),"count").withColumnRenamed("concat(DisplayName0, ,Version0)", "software").collect()
        df_most_vuln_onbe = self.sccmDF.filter('Zone_X="ONBE"').select('DisplayName0','Version0').groupBy('DisplayName0','Version0').count().orderBy(desc('count')).limit(10)\
        .select(concat(col("DisplayName0"),lit(" "),col("Version0")),"count").withColumnRenamed("concat(DisplayName0, ,Version0)", "software").collect()
        df_most_vuln_corp = self.sccmDF.filter('Zone_X="Corp"').select('DisplayName0','Version0').groupBy('DisplayName0','Version0').count().orderBy(desc('count')).limit(10)\
        .select(concat(col("DisplayName0"),lit(" "),col("Version0")),"count").withColumnRenamed("concat(DisplayName0, ,Version0)", "software").collect()
        df_most_vuln_func = self.sccmDF.select('HostFn_X').groupBy('HostFn_X').count().orderBy(desc('count')).limit(10).collect()


        dataChart = []
        descriptionChart = {
            "software": ("string", "Software"),
            "hits": ("number", "Hits")
        }
        for row in df_most_vuln:
            dataChart.append(
                {
                    "software": row.software,
                    "hits": int(row[1])
                }
            )
        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        json_most_vuln = data_tableChart.ToJSon(
            columns_order=("software","hits"),
            order_by="hits"
        )

        dataChart = []
        for row in df_ncsa_most_vuln:
            dataChart.append(
                {
                    "software": row.software,
                    "hits": int(row[1])
                }
            )
        data_tableChart.LoadData(dataChart)
        json_most_vuln_ncsa = data_tableChart.ToJSon(
            columns_order=("software","hits"),
            order_by="hits"
        )

        dataChart = []
        for row in df_emea_most_vuln:
            dataChart.append(
                {
                    "software": row.software,
                    "hits": int(row[1])
                }
            )
        data_tableChart.LoadData(dataChart)
        json_most_vuln_emea = data_tableChart.ToJSon(
            columns_order=("software","hits"),
            order_by="hits"
        )

        dataChart = []
        for row in df_apac_most_vuln:
            dataChart.append(
                {
                    "software": row.software,
                    "hits": int(row[1])
                }
            )
        data_tableChart.LoadData(dataChart)
        json_most_vuln_apac = data_tableChart.ToJSon(
            columns_order=("software","hits"),
            order_by="hits"
        )

        dataChart = []
        for row in df_most_vuln_onbe:
            dataChart.append(
                {
                    "software": row.software,
                    "hits": int(row[1])
                }
            )
        data_tableChart.LoadData(dataChart)
        json_most_vuln_onbe = data_tableChart.ToJSon(
            columns_order=("software","hits"),
            order_by="hits"
        )

        dataChart = []
        for row in df_most_vuln_corp:
            dataChart.append(
                {
                    "software": row.software,
                    "hits": int(row[1])
                }
            )
        data_tableChart.LoadData(dataChart)
        json_most_vuln_corp = data_tableChart.ToJSon(
            columns_order=("software","hits"),
            order_by="hits"
        )

        dataChart = []
        descriptionChart = {
            "function": ("string", "Host function"),
            "hits": ("number", "Hits")
        }
        for row in df_most_vuln_func:
            dataChart.append(
                {
                    "function": row.HostFn_X,
                    "hits": int(row[1])
                }
            )
        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        json_most_vuln_func = data_tableChart.ToJSon(
            columns_order=("function","hits"),
            order_by="hits"
        )
        return json_most_vuln,json_most_vuln_ncsa,json_most_vuln_emea,json_most_vuln_apac,json_most_vuln_onbe,json_most_vuln_corp,json_most_vuln_func

    def getCmdPrediction(self):
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        df = self.session.read.parquet('/user/jleaniz/ml/kmeans_new')
        outliers = df.groupBy("prediction").count().filter('count < 20').withColumnRenamed("prediction", "cluster")
        self.outlierCmds = outliers.join(df, df.prediction == outliers.cluster).distinct()
        result = []
        for row in self.outlierCmds.collect():
            result.append(' '.join(row.command) + ' -> Seen on: ' + row.date)

        return result

    def getVPNLoginsGeoMap(self):
        self.sc.setLocalProperty("spark.scheduler.pool", "dashboard")

        adlocation = self.session.read.format('com.databricks.spark.csv')\
            .options(header='true',inferschema='true').load('ad.csv').filter('c not like ""')

        adlocation.cache()

        vpn = self.session.read.parquet('/user/jleaniz/ciscovpn')
        vpn.cache()

        def func(x):
            gi = GeoIP.open("GeoIP.dat",GeoIP.GEOIP_MEMORY_CACHE)
            cc = gi.country_code_by_addr(x.remoteip)
            return Row(bytesrcv=x.bytesrcv, bytesxmt=x.bytesxmt, duration=x.duration, localip=x.localip, reason=x.reason,
                       remoteip=x.remoteip, source=x.source, time=x.time, user=x.user, date=x.date, remoteipcc=cc)

        vpnDF = vpn.map(func).toDF()
        joinDF = vpnDF.join(adlocation, vpnDF.user == adlocation.EmailAddress)
        joinDF.cache()

        fromOtherLocations = joinDF.filter("remoteipcc <> c")
        countbyCountry = fromOtherLocations.groupBy(fromOtherLocations.remoteipcc).count().orderBy(desc('count'))
        entries = countbyCountry.collect()

        # Build json object for the table
        dataChart = []
        descriptionChart = {
            "remoteipcc": ("string", "RemoteIP CC"),
            "count": ("number", "Count")
        }

        for entry in entries:
            dataChart.append({"remoteipcc": entry.remoteipcc, "count": int(entry[1])})

        data_tableChart = gviz_api.DataTable(descriptionChart)
        data_tableChart.LoadData(dataChart)
        # Creating a JSon string
        vpn_logins = data_tableChart.ToJSon(
            columns_order=("remoteipcc", "count"),
            order_by="count"
        )
        return vpn_logins

def init_spark_context():
    appConfig = conf.Config(exec_cores=2, cores_max=24, yarn_cores=8, instances=8, queue='root.llama')
    sc = SparkContext(conf=appConfig.setSparkConf())
    # set resource pool
    sc.setLocalProperty("spark.scheduler.pool", "default")
    return sc

sc = init_spark_context()
analytics_engine = AnalyticsEngine(sc)


def buildJSON(tables, fromdate, todate, query, num):
    jsonResult = analytics_engine.getSearchResults(tables, fromdate, todate, query, num)
    results = []

    results.append('{"%s": [\n' % ("search"))
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

