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
import urllib2
import re
from pyspark.sql import Row
from pyspark import SparkContext


class Parser(object):
    '''
    This class has methods to parse different types of data.
    Currently support data is as follows:
    - Volatility Framework (imageinfo, pslist)
    - Netfilter IPtables (custom format)
    - Blue Coat ProxySG access logs (custom format)
    - Threat intelligence feeds:
        Custom C2 database
        OpenPhish
        AlienVault OTX
        TODO: C1fapp
    '''

    def __init__(self):
        '''
        Init function for Parser class
        Initializes type and patterns attributes

        :param patterns:
        :return:
        '''

        self.patterns = {
            'sgAccessLog': re.compile(
                '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) (\w+-\w+-\w+|"\w+-\w+-\w+") "(\d+)-(\d+)-(\d+)" ' \
                '' \
                '' \
                '"(\d+:\d+:\d+)" "(\d+)" "(\d+.\d+.\d+.\d+)" "(\d+)" "(\S+)" "(\d+)" "(\d+)" "(\w+)" "(\w+)" "(' \
                '\d+.\d+.\d+.\d+|\S+)" "(\d+)" "(\S+)" "(\S+)" "(\S+)" "(\S+)" "(\d+.\d+.\d+.\d+|\S+)" "(\S+)" "(' \
                '\S+)" "([^"].*?)" "(\S+)" "([\s\S]*?)" "(\S+)" "(\d+.\d+.\d+.\d+)"'
            ),
            'sgAccessLogSSL': re.compile(
                '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) (\w+-\w+-\w+|"\w+-\w+-\w+") (\d+)-(' \
                '\d+)-(\d+) (\d+:\d+:\d+) (\d+) (\d+.\d+.\d+.\d+) (\d+) (\S+) (\d+) (\d+) (\w+) (\w+) (' \
                '\d+.\d+.\d+.\d+|\S+) (\d+) (\S+) (\S+) (\S+) (\S+) (\d+.\d+.\d+.\d+|\S+) (\S+) (\S+) ' \
                '"?([' \
                '^"].*?)"? (\S+) "([\s+\S+]*?)" (\S+) (\S+) (\d{3}|\S+) (\S+) (\d+.\d+.\d+.\d+)'
            ),
            'iptables': re.compile(
                '(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) '
                '(\S+)(' \
                '\s{1,2})IN=(\S+) OUT=((\S+)?) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+   .\d+.\d+) LEN=(\d+) '
                'TOS=('
                '\d+) ' \
                'PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)'
            ),
            'bashlog': re.compile(
                "(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) bash: user: (\S+) as (\S+) from ip: ("
                "\d+.\d+.\d+.\d+|\S+):pts\/\d{1,2} execs: '(.*)'"
            ),
            'bashlogWarn': re.compile(
                "(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) bash: WARNING (.*) execs '(.*)'"
            ),
            'ciscovpnLogin': re.compile(
                '(\d\d\d\d-\d\d-\d\d)T(\d\d:\d\d:\d\d)\+\d\d:\d\d (\S+) : %ASA-\d-722051: \S+ \S+ User <(\S+)> IP <('
                '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})> IPv4 Address <(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})>'
            ),
            'ciscovpnLogout': re.compile(
                '(\d\d\d\d-\d\d-\d\d)T(\d\d:\d\d:\d\d)\+\d\d:\d\d (\S+) : %ASA-\d-113019: Group = \S+ Username = ('
                '\S+), IP = (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}), Session disconnected. Session Type: \S+, Duration: (\d{'
                '1,3}h:\d{1,2}m:\d{1,2}s), Bytes xmt: (\d+), Bytes rcv: (\d+), Reason: (.*)'
            ),
            'apacheAccessLog': re.compile(
                "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(\\S+) (\\S+) (\\S+)\" (\\d{3}) (\\d+)"
            )
        }

    def parseBCAccessLog(self, partition):
        '''
        Parse ProxySG access logs
        :return: pyspark.sql.Row
        '''
        patterns = [self.patterns['sgAccessLog'],
                    self.patterns['sgAccessLogSSL']
                    ]

        for element in partition:
            for pattern in patterns:
                m = re.search(pattern, element)
                if m:
                    if pattern == patterns[0]:
                        yield Row(
                            proxy=m.group(2),
                            time=m.group(6),
                            timetaken=m.group(7),
                            clientip=m.group(8),
                            scstatus=m.group(9),
                            saction=m.group(10),
                            scbytes=int(m.group(11)),
                            csbytes=int(m.group(12)),
                            method=m.group(13),
                            urischeme=m.group(14),
                            host=m.group(15),
                            port=int(m.group(16)),
                            path=m.group(17),
                            query=m.group(18),
                            username=m.group(19),
                            group=m.group(20),
                            sname=m.group(21),
                            contenttype=m.group(22),
                            referer=m.group(23),
                            agent=m.group(24),
                            action=m.group(25),
                            categories=m.group(26),
                            tlsver='',
                            tlscipher='',
                            ciphersize='',
                            malware=m.group(27),
                            proxyip=m.group(28)
                        )

                    elif pattern == patterns[1]:
                        yield Row(
                            proxy=m.group(2),
                            time=m.group(6),
                            timetaken=m.group(7),
                            clientip=m.group(8),
                            scstatus=m.group(9),
                            saction=m.group(10),
                            scbytes=int(m.group(11)),
                            csbytes=int(m.group(12)),
                            method=m.group(13),
                            urischeme=m.group(14),
                            host=m.group(15),
                            port=int(m.group(16)),
                            path=m.group(17),
                            query=m.group(18),
                            username=m.group(19),
                            group=m.group(20),
                            sname=m.group(21),
                            contenttype=m.group(22),
                            referer=m.group(23),
                            agent=m.group(24),
                            action=m.group(25),
                            categories=m.group(26),
                            tlsver=m.group(27),
                            tlscipher=m.group(28),
                            ciphersize=int(m.group(29)),
                            malware=m.group(30),
                            proxyip=m.group(31)
                        )

    def parseVPN(self, partition):
        '''
        Parse Cisco VPN logs
        :return: pyspark.sql.Row
        '''
        patterns = [self.patterns['ciscovpnLogin'],
                    self.patterns['ciscovpnLogout']
                    ]

        for element in partition:
            for pattern in patterns:
                m = re.search(pattern, element)
                if m:
                    if pattern == patterns[0]:
                        yield Row(
                            date=m.group(1),
                            time=m.group(2),
                            server=m.group(3),
                            user=m.group(4),
                            remoteip=m.group(5),
                            localip=m.group(6),
                            duration='',
                            bytesxmt='',
                            bytesrcv='',
                            reason='',
                        )

                    elif pattern == patterns[1]:
                        yield Row(
                            date=m.group(1),
                            time=m.group(2),
                            server=m.group(3),
                            user=m.group(4),
                            remoteip=m.group(5),
                            localip='',
                            duration=m.group(6),
                            bytesxmt=m.group(7),
                            bytesrcv=m.group(8),
                            reason=m.group(9)
                        )

    def parseIPTables(self, partition):
        '''
        Parse Netfilter IPtables
        :return: pyspark.sql.Row
        '''

        fwlog = self.patterns['iptables']
        for element in partition:
            m = re.search(fwlog, element)
            if m:
                yield Row(
                    time=m.group(4),
                    source=m.group(5),
                    action=m.group(9),
                    srcip=m.group(15),
                    dstip=m.group(16),
                    len=int(m.group(17)),
                    ttl=int(m.group(20)),
                    proto=m.group(22),
                    srcport=int(m.group(23)),
                    dstport=int(m.group(24))
                )

    def parseBash(self, partition):
        """
        Parse bash logs
        :param partition:
        :return: Row
        """

        patterns = [self.patterns['bashlog'],
                    self.patterns['bashlogWarn']
                    ]

        for element in partition:
            for pattern in patterns:
                m = re.search(pattern, element)
                if m:
                    yield Row(
                        logsrc=m.group(5),
                        username=m.group(6),
                        exec_as=m.group(7),
                        srcip=m.group(8),
                        command=m.group(9)
                    )

    def parseApacheAL(self, partition):
        '''
        Parse Apache access logs
        :return: pyspark.sql.Row
        '''
        pattern = self.patterns['apacheAccessLog']
        for element in partition:
            m = re.search(pattern, element)
            if m:
                yield Row(
                    ip_address=m.group(1),
                    client_identd=m.group(2),
                    user_id=m.group(3),
                    date_time=m.group(4),
                    method=m.group(5),
                    endpoint=m.group(6),
                    protocol=m.group(7),
                    response_code=int(m.group(8)),
                    content_size=long(m.group(9))
                )

    def parseAlienVaultOTX(self, data):
        '''
        Parse AlienVault OTX reputation data
        :return: pyspark.sql.Row
        '''
        for line in data:
            params = data.split('#')
            return Row(
                ip=params[0],
                reason=params[3]
            )

    def parsec2(self, data):
        '''
        Parse c2 reputation database
        :return: pyspark.sql.Row
        '''
        VALID_DATA = '(\d+.\d+.\d+.\d+|(\S+\.\S+))'
        m = re.search(VALID_DATA, data)
        if m:
            return Row(
                host=data,
                reason='C2'
            )
        else:
            return Row(host='', reason='')

    def parseOpenPhish(self, data):
        '''
        Parse OpenPhish reputation data
        :return: pyspark.sql.Row
        '''
        return Row(
            url=data.strip(),
            reason='OpenPhish'
        )


    '''
    netflow v9 is hard to parse
    Easiest way to do this is to have a box collecting netflows with
    nfcapd and then use Spark to execute nfdump to convert nfcapd files to CSV
    to ingest as parquet files
    '''
    def parseNetflow(self, file):
        pass

    '''
    def parseImageInfo(self, img_path, lines):
        Parse Volatility framework imageinfo command output
        :return: pyspark.sql.Row
        PROFILES_PATTERN = "(\w+)(\s)(\w+)(\S+)(\s)(\:)(\s)(\S+)"
        KDBG_PATTERN = "(\KDBG)(\s:\s)(\w+)"

        for line in lines:
            profile = re.search(PROFILES_PATTERN, line)
            kdbg = re.search(KDBG_PATTERN, line)

            if profile:
                if 'Profile' in line:
                    m_profile = profile.group(8)

            if kdbg:
                m_kdbg = kdbg.group(3)

        return Row(
            image=img_path,
            profile=m_profile.rstrip(','),
            kdbg=m_kdbg
        )
    '''

    '''
    def parsePSList(self, img_path, lines):

        Parse Volatility framework pslist command output
        :return: pyspark.sql.Row

        PSLIST_PATTERN = "(\w+)(\s+)(\w+.+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d{" \
                         "4}-\d\d-\d\d\s\d\d:\d\d:\d\d)"
        proclist = []

        for line in lines:
            m = re.search(PSLIST_PATTERN, line)
            if m:
                proclist.append(m.group(3).strip())

        return Row(
            image=img_path,
            proclist=proclist
        )
    '''
