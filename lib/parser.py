import urllib2
import re
from pyspark.sql import Row


class Parser:
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

    def __init__(self, type):
        self.type = ''

    def parseImageInfo(self, img_path, lines):
        '''
        Parse Volatility framework imageinfo command output
        :return: pyspark.sql.Row
        '''
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

    def parsePSList(self, img_path, lines):
        '''
        Parse Volatility framework pslist command output
        :return: pyspark.sql.Row
        '''
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

    def parseBCAccessLog(self, partition):
        '''
        Parse ProxySG access logs
        :return: pyspark.sql.Row
        '''

        ACCESS_HTTP = re.compile(
            '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) (\w+-\w+-\w+|"\w+-\w+-\w+") "(\d+)-(\d+)-(\d+)" ' \
            '' \
            '' \
            '"(\d+:\d+:\d+)" "(\d+)" "(\d+.\d+.\d+.\d+)" "(\d+)" "(\S+)" "(\d+)" "(\d+)" "(\w+)" "(\w+)" "(' \
            '\d+.\d+.\d+.\d+|\S+)" "(\d+)" "(\S+)" "(\S+)" "(\S+)" "(\S+)" "(\d+.\d+.\d+.\d+|\S+)" "(\S+)" "(' \
            '\S+)" "([^"].*?)" "(\S+)" "([\s\S]*?)" "(\S+)" "(\d+.\d+.\d+.\d+)"')
        ACCESS_HTTPS = re.compile(
            '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) (\w+-\w+-\w+|"\w+-\w+-\w+") (\d+)-(' \
            '\d+)-(\d+) (\d+:\d+:\d+) (\d+) (\d+.\d+.\d+.\d+) (\d+) (\S+) (\d+) (\d+) (\w+) (\w+) (' \
            '\d+.\d+.\d+.\d+|\S+) (\d+) (\S+) (\S+) (\S+) (\S+) (\d+.\d+.\d+.\d+|\S+) (\S+) (\S+) ' \
            '"?([' \
            '^"].*?)"? (\S+) "([\s+\S+]*?)" (\S+) (\S+) (\d{3}|\S+) (\S+) (\d+.\d+.\d+.\d+)')

        PATTERNS = [ACCESS_HTTP, ACCESS_HTTPS]

        for element in partition:
            for pattern in PATTERNS:
                m = re.search(pattern, element)
                if m:
                    if pattern == ACCESS_HTTP:
                        yield Row(
                            proxy=m.group(2),
                            time=m.group(6),
                            timetaken=m.group(7),
                            clientip=m.group(8),
                            scstatus=m.group(9),
                            saction=m.group(10),
                            scbytes=m.group(11),
                            csbytes=m.group(12),
                            method=m.group(13),
                            urischeme=m.group(14),
                            host=m.group(15),
                            port=m.group(16),
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

                    elif pattern == ACCESS_HTTPS:
                        yield Row(
                            proxy=m.group(2),
                            time=m.group(6),
                            timetaken=m.group(7),
                            clientip=m.group(8),
                            scstatus=m.group(9),
                            saction=m.group(10),
                            scbytes=m.group(11),
                            csbytes=m.group(12),
                            method=m.group(13),
                            urischeme=m.group(14),
                            host=m.group(15),
                            port=m.group(16),
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
                            ciphersize=m.group(29),
                            malware=m.group(30),
                            proxyip=m.group(31)
                        )

    def parseIPTables(self, partition):
        '''
        Parse Netfilter IPtables
        :return: pyspark.sql.Row
        '''
        LOG = re.compile(
            '(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) (\S+)(' \
            '\s{1,2})IN=(\S+) OUT=((\S+)?) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+.\d+.\d+) LEN=(\d+) TOS=(\d+) ' \
            'PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)')
        for element in partition:
            m = re.search(LOG, element)
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

    def parseApacheAL(self,partition):
        '''
        Parse Apache access logs
        :return: pyspark.sql.Row
        '''
        pattern = re.compile(
            "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(\\S+) (\\S+) (\\S+)\" (\\d{3}) (\\d+)")
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
