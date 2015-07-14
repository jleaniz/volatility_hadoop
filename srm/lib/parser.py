import urllib2
import re
from pyspark.sql import Row

def parseImageInfo(img_path, lines):
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
        image = img_path,
        profile = m_profile.rstrip(','),
        kdbg = m_kdbg
        )

def parsePSList(img_path, lines):
    PSLIST_PATTERN = "(\w+)(\s+)(\w+.+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\d{4}-\d\d-\d\d\s\d\d:\d\d:\d\d)"
    proclist = []

    for line in lines:
        m = re.search(PSLIST_PATTERN, line)
        if m:
            proclist.append(m.group(3).strip())

    return Row(
        image = img_path,
        proclist = proclist
        )

def parseBCAccessLog(partition):
    ACCESS_HTTP = '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) (\w+-\w+-\w+|"\w+-\w+-\w+") "(\d+)-(\d+)-(\d+)" "(\d+:\d+:\d+)" "(\d+)" "(\d+.\d+.\d+.\d+)" "(\d+)" "(\S+)" "(\d+)" "(\d+)" "(\w+)" "(\w+)" "(\d+.\d+.\d+.\d+|\S+)" "(\d+)" "(\S+)" "(\S+)" "(\S+)" "(\S+)" "(\d+.\d+.\d+.\d+|\S+)" "(\S+)" "(\S+)" "([^"].*?)" "(\S+)" "([\s\S]*?)" "(\S+)" "(\d+.\d+.\d+.\d+)"'
    ACCESS_HTTPS_INTERCEPT = '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) (\w+-\w+-\w+|"\w+-\w+-\w+") (\d+)-(\d+)-(\d+) (\d+:\d+:\d+) (\d+) (\d+.\d+.\d+.\d+) (\d+) (\S+) (\d+) (\d+) (\w+) (\w+) (\d+.\d+.\d+.\d+|\S+) (\d+) (\S+) (\S+) (\S+) (\S+) (\d+.\d+.\d+.\d+|\S+) (\S+) (\S+) "?([^"].*?)"? (\S+) "([\s+\S+]*?)" (\S+) (\S+) (\d{3}|\S+) (\S+) (\d+.\d+.\d+.\d+)'

    PATTERNS = [ACCESS_HTTP, ACCESS_HTTPS_INTERCEPT]

    for element in partition:
        for pattern in PATTERNS:
            m = re.search(pattern, element)
            if m:
                if pattern == ACCESS_HTTP:
                    yield Row(
                            proxy = m.group(2),
                            time = m.group(6),
                            timetaken = m.group(7),
                            clientip = m.group(8), 
                            scstatus = m.group(9),
                            saction = m.group(10), 
                            scbytes = m.group(11),
                            csbytes = m.group(12),
                            method = m.group(13),
                            urischeme = m.group(14),
                            host = m.group(15), 
                            port = m.group(16),
                            path = m.group(17), 
                            query = m.group(18), 
                            username = m.group(19),
                            group = m.group(20),
                            sname = m.group(21),
                            contenttype = m.group(22),
                            referer = m.group(23),
                            agent = m.group(24),
                            action = m.group(25),
                            categories = m.group(26),
                            tlsver = '',
                            tlscipher = '',
                            ciphersize = '',
                            malware = m.group(27),
                            proxyip = m.group(28)
                            )

                elif pattern == ACCESS_HTTPS_INTERCEPT:
                    yield Row(
                            proxy = m.group(2),
                            time = m.group(6),
                            timetaken = m.group(7),
                            clientip = m.group(8), 
                            scstatus = m.group(9),
                            saction = m.group(10), 
                            scbytes = m.group(11),
                            csbytes = m.group(12),
                            method = m.group(13),
                            urischeme = m.group(14),
                            host = m.group(15), 
                            port = m.group(16),
                            path = m.group(17), 
                            query = m.group(18), 
                            username = m.group(19),
                            group = m.group(20),
                            sname = m.group(21),
                            contenttype = m.group(22),
                            referer = m.group(23),
                            agent = m.group(24),
                            action = m.group(25),
                            categories = m.group(26),
                            tlsver = m.group(27),
                            tlscipher = m.group(28),
                            ciphersize = m.group(29),
                            malware = m.group(30),
                            proxyip = m.group(31)
                            )


def parseIPTables(partition):
    LOG = '(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) (\S+)(\s{1,2})IN=(\S+) OUT=((\S+)?) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+.\d+.\d+) LEN=(\d+) TOS=(\d+) PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)'
    for element in partition:
        m = re.search(LOG, element)
        if m:
            yield Row(
                time = m.group(4),
                source = m.group(5),
                action = m.group(9),
                srcip = m.group(15),
                dstip = m.group(16),
                len = int(m.group(17)),
                ttl = int(m.group(20)),
                proto = m.group(22),
                srcport = int(m.group(23)),
                dstport = int(m.group(24))
                )

'''
FREE SECURITY INTELLIGENCE FEEDS
===================================
http://mirror1.malwaredomains.com/files/domains.txt
Google Safe Browsing Lookup API v2 key=AIzaSyD95TqDy9OpxnggJCTbG3aeVsmE_eUDRd4
http://www.malwaredomainlist.com/hostslist/hosts.txt
https://lists.malwarepatrol.net/cgi/getfile?receipt=f1434725867&product=8&list=dansguardian
http://data.phishtank.com/data/<your app key>/online-valid.csv.bz2 181c91b14a9ec82fcaaa4683c3fbceb2c58b149def949298be81e5a1f3986978
https://openphish.com/feed.txt
http://www.dshield.org/ipsascii.html?limit=10000
http://osint.bambenekconsulting.com/feeds/c2-masterlist.txt
http://rules.emergingthreats.net/blockrules/emerging-botcc.rules
http://rules.emergingthreats.net/blockrules/emerging-drop-BLOCK.rules
http://rules.emergingthreats.net/blockrules/emerging-compromised.rules
http://rules.emergingthreats.net/blockrules/emerging-compromised-BLOCK.rules
http://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules
http://rules.emergingthreats.net/blockrules/emerging-tor.rules
http://rules.emergingthreats.net/blockrules/compromised-ips.txt
http://atlas.arbor.net/summary/fastflux.csv
https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist
https://zeustracker.abuse.ch/blocklist.php?download=compromised
https://sslbl.abuse.ch/downloads/ssl_extended.csv
http://www.montanamenagerie.org/hostsfile/hosts.txt
http://malc0de.com/bl/IP_Blacklist.txt
http://reputation.alienvault.com/reputation.data
'''

def parseAlienVaultOTX(data):
    for line in data:
        params = data.split('#')
        return Row(
            ip = params[0],
            reason = params[3]
            )

def parsec2(data):
    VALID_DATA = '(\d+.\d+.\d+.\d+|(\S+\.\S+))'
    m = re.search(VALID_DATA, data)
    if m:
        return Row(
            host = data, 
            reason = 'C2'
            )
    else:
        return Row(host='', reason='')

def parseOpenPhish(data):
    return Row(
        url = data.strip(),
        reason = 'OpenPhish'
        )
