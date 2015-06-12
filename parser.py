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