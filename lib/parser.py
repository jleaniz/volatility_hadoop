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
    LOG = '(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) (\S+) (\S+)  (RULE \S+ \d+|RULE \d+) (\S+) (\S+)(\s{1,2})IN=(\S+) OUT=(\S+) MAC=(\S+)  SRC=(\d+.\d+.\d+.\d+) DST=(\d+.\d+.\d+.\d+) LEN=(\d+) TOS=(\d+) PREC=(\S+) TTL=(\d+) ID=(\d+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)'
    for element in partition:
        m = re.search(LOG, element)
        if m:
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

