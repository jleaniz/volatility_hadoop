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

from impala.dbapi import connect

class ImpalaDB:
    '''
    This class defines methods used to interact with
    an Impala database
    '''
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self, host, port):
        '''
        :param host: Impala server hostname
        :param port: Impala server port
        :return: impyla cursor
        '''
        conn = connect(host=self.host, port=self.port)
        cursor = conn.cursor()
        return cursor

    def createTable(self, cursor, table, partitions, schemaFile, location, ):
        '''
        Create an Impala database
        :param cursor:
        :param table:
        :param partitions:
        :param schemaFile:
        :param location:
        :return:
        '''
        try:
            cursor.execute(
                'CREATE EXTERNAL TABLE IF NOT EXISTS %s LIKE PARQUET %s \
                PARTITIONED BY (year smallint, month smallint, day smallint) \
                STORED AS PARQUET \
                LOCATION %s' % (table, schemaFile, location)
            )
        except:
            pass

    def addPartitions(self, cursor, table, year, month, day):
        '''
        Add partitions to a table
        :param cursor:
        :param table:
        :param year:
        :param month:
        :param day:
        :return:
        '''
        try:
            cursor.execute(
                # 'alter table ' + table + 'add partition (year=' + year + ', month=' + month + ', day=' + day + ')'
                'ALTER TABLE %s add partition (%s, %s, %s)' % (table, year, month, day)
            )
        except:
            pass

    def loadData(self, cursor, table, path, partitions):
        '''
        Load data into a partitioned table
        :param cursor:
        :param table:
        :param path:
        :param partitions:
        :return:
        '''
        try:
            cursor.execute(
                'LOAD DATA INPATH %s INTO TABLE %s PARTITION (year=%s, month=%s, day=%s)' % (
                path + '/year=' + partitions[0] + '/month=' + partitions[1] + '/day=' + partitions[2],
                table, partitions[0], partitions[1], partitions[2])
            )
        except:
            pass
