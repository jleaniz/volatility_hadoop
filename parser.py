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
    '''
    s-computername date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-rs-connection-negotiated-ssl-version x-rs-connection-negotiated-cipher x-rs-connection-negotiated-cipher-size x-virus-id s-ip
    s-computername date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-rs-connection-negotiated-ssl-version x-rs-connection-negotiated-cipher x-rs-connection-negotiated-cipher-size x-virus-id s-ip
    s-computername date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-virus-id s-ip
    s-computername date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-virus-id s-ip
    '''
    ACCESS_HTTP = '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) "(\w+-\w+-\w+)" "(\d+-\d+-\d+)" "(\d+:\d+:\d+)" "(\d+)" "(\d+.\d+.\d+.\d+)" "(\d+)" "(\S+)" "(\d+)" "(\d+)" "(\w+)" "(\w+)" "(\d+.\d+.\d+.\d+|\S+)" "(\d+)" "(\S+)" "(\S+)" "(\S+)" "(\S+)" "(\d+.\d+.\d+.\d+|\S+)" "(\S+)" "(\S+)" "([^"].*?)" "(\S+)" "([\s\S]*?)" "(\S+)" "(\d+.\d+.\d+.\d+)"'
    ACCESS_HTTPS_INTERCEPT = '(\d+-\d+-\d+T\d+:\d+:\d+\+\d+:\d+ msr-net-bcrep01) "(\w+-\w+-\w+)" (\d+-\d+-\d+) (\d+:\d+:\d+) (\d+) (\d+.\d+.\d+.\d+) (\d+) (\S+) (\d+) (\d+) (\w+) (\w+) (\d+.\d+.\d+.\d+|\S+) (\d+) (\S+) (\S+) (\S+) (\S+) (\d+.\d+.\d+.\d+|\S+) (\S+) (\S+) "?([^"].*?)"? (\S+) "([\s+\S+]*?)" (\S+) (\S+) (\d{3}|\S+) (\S+) (\d+.\d+.\d+.\d+)'

    PATTERNS = [ACCESS_HTTP, ACCESS_HTTPS_INTERCEPT]

    for element in partition:
        for pattern in PATTERNS:
            m = re.search(pattern, element)
            if m:
                if pattern == ACCESS_HTTP:
                    yield Row(
                            proxy = m.group(2),
                            date = m.group(3),
                            time = m.group(4),
                            timetaken = m.group(5),
                            clientip = m.group(6), 
                            scstatus = m.group(7),
                            saction = m.group(8), 
                            scbytes = m.group(9),
                            csbytes = m.group(10),
                            method = m.group(11),
                            urischeme = m.group(12),
                            host = m.group(13), 
                            port = m.group(14),
                            path = m.group(15), 
                            query = m.group(16), 
                            username = m.group(17),
                            group = m.group(18),
                            sname = m.group(19),
                            contenttype = m.group(20),
                            referer = m.group(21),
                            agent = m.group(22),
                            action = m.group(23),
                            categories = m.group(24),
                            tlsver = '',
                            tlscipher = '',
                            ciphersize = '',
                            malware = m.group(25),
                            proxyip = m.group(26)
                            )

                elif pattern == ACCESS_HTTPS_INTERCEPT:
                    yield Row(
                            proxy = m.group(2),
                            date = m.group(3),
                            time = m.group(4),
                            timetaken = m.group(5),
                            clientip = m.group(6), 
                            scstatus = m.group(7),
                            saction = m.group(8), 
                            scbytes = m.group(9),
                            csbytes = m.group(10),
                            method = m.group(11),
                            urischeme = m.group(12),
                            host = m.group(13), 
                            port = m.group(14),
                            path = m.group(15), 
                            query = m.group(16), 
                            username = m.group(17),
                            group = m.group(18),
                            sname = m.group(19),
                            contenttype = m.group(20),
                            referer = m.group(21),
                            agent = m.group(22),
                            action = m.group(23),
                            categories = m.group(24),
                            tlsver = m.group(25),
                            tlscipher = m.group(26),
                            ciphersize = m.group(27),
                            malware = m.group(28),
                            proxyip = m.group(29)
                            )


def parseIPTables(partition):
    '''
    2015-06-16T00:00:00+00:00 msr-off-fw03 ulogd[11609]:  RULE 777 -- ACCEPT  IN=bond1.15 OUT=bond0.702 MAC=90:e2:ba:5f:1e:21:00:11:5d:ff:10:00:08:00  SRC=70.29.98.14 DST=216.98.57.48 LEN=52 TOS=00 PREC=0x00 TTL=116 ID=10786 DF PROTO=TCP SPT=61567 DPT=443 SEQ=2361467354 ACK=0 WINDOW=8192 SYN URGP=0 
    2015-06-16T00:00:00+00:00 msr-off-fw03 ulogd[11609]:  RULE 1236 -- DENY  IN=bond0.900 OUT=bond0.900 MAC=90:e2:ba:5f:1e:20:00:64:40:3a:74:80:08:00  SRC=10.140.40.109 DST=10.140.41.255 LEN=229 TOS=00 PREC=0x00 TTL=124 ID=29713 PROTO=UDP SPT=138 DPT=138 LEN=209 
    2015-06-16T00:00:00+00:00 msr-off-fw03 ulogd[11609]:  RULE LunchGamer 94 -- ACCEPT IN=bond0.900 OUT=bond1.15 MAC=90:e2:ba:5f:1e:20:00:64:40:3a:74:80:08:00  SRC=10.140.34.67 DST=208.78.164.9 LEN=64 TOS=00 PREC=0x00 TTL=124 ID=28731 PROTO=UDP SPT=63033 DPT=27018 LEN=44 
    '''
    #TCP_LOG = '(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) (\S+)(\s{1,2})IN=(\S+) OUT=(\S+) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+.\d+.\d+) LEN=(\d+) TOS=(\d+) PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+) SEQ=(\d+) ACK=(\d+) WINDOW=(\d+) (.*)'
    #UDP_LOG = '(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) (\S+)(\s{1,2})IN=(\S+) OUT=(\S+) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+.\d+.\d+) LEN=(\d+) TOS=(\d+) PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)'

    LOG = '(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) (\S+)(\s{1,2})IN=(\S+) OUT=(\S+) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+.\d+.\d+) LEN=(\d+) TOS=(\d+) PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)'

    #PATTERNS = [TCP_LOG, UDP_LOG]

    for element in partition:
        #for pattern in PATTERNS:
            #m = re.search(patter, element)
        m = re.search(LOG, element)
        if m:
            #if pattern == TCP_LOG:
            yield Row(
                date = m.group(1),
                time = m.group(2),
                source = m.group(3),
                action = m.group(7),
                srcip = m.group(12),
                dstip = m.group(13),
                len = m.group(14),
                ttl = m.group(17),
                proto = m.group(19),
                srcport = m.group(20),
                dstport = m.group(21)
                #flags = m.group(25)
                )
            #elif pattern == UDP_LOG:
            #    yield Row(
            #        date = m.group(1),
            #        time = m.group(2),
            #        source = m.group(3),
            #        action = m.group(7),
            #        srcip = m.group(12),
            #        dstip = m.group(13),
            #        len = m.group(14),
            #        ttl = m.group(17),
            #        proto = m.group(19),
            #        srcport = m.group(20),
            #        dstport = m.group(21),
            #        flags = ''
            #        )