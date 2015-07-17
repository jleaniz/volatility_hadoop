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
import urllib
import re
# import netaddr
import lib.parser as parser
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def get_c2_feeds():
    results = []
    urls = ['http://osint.bambenekconsulting.com/feeds/c2-masterlist.txt',
            'http://rules.emergingthreats.net/fwrules/emerging-IPF-ALL.rules',
            'https://lists.malwarepatrol.net/cgi/getfile?'
            'http://mirror1.malwaredomains.com/files/domains.txt',
            'http://www.montanamenagerie.org/hostsfile/hosts.txt'
            ]

    for url in urls:
        if 'montanamenagerie.org' in url:
            print 'Updating db from montanamenagerie.org'
            f = urllib.urlopen(url)
            data = f.read().split('\r\n')
            for line in data:
                element = line.split('\t')
                if '#' not in element:
                    if len(element) >= 2:
                        domain = element[1]
                        # if domain not in results:
                        results.append(domain)

        if 'malwaredomains.com' in url:
            print 'Updating db from malwaredomains.com'
            f = urllib.urlopen(url)
            data = f.read().split('\r\n')
            for line in data:
                element = line.split('\t')
                if len(element) >= 6:
                    domain = element[2]
                    # if domain not in results:
                    results.append(domain)

        if 'emergingthreats.net' in url:
            print 'Updating db from emergingthreats.net'
            f = urllib.urlopen(url)
            data = f.read().split('\n')
            for line in data:
                acl = line.split()
                if len(acl) == 8:
                    if re.search('(\d+.\d+.\d+.\d+)|(\d+.\d+.\d+.\d+\/\d+)', acl[5]):
                        ip = acl[5]
                        results.append(ip)
                        # for ipaddr in netaddr.IPNetwork(ip):
                        #	if ipaddr not in results:
                        #	results.append(ipaddr)

        if 'bambenekconsulting.com' in url:
            print 'Updating db from bambenekconsulting.com'
            f = urllib.urlopen(url)
            data = f.read().split('\n')
            for line in data:
                domain = line.split(',')[0].strip()
                # if domain not in results:
                results.append(domain)

        if 'malwarepatrol.net' in url:
            print 'Updating db from malwarepatrol.net'
            params = urllib.urlencode({'receipt': 'f1434725867', 'product': 8, 'list': 'dansguardian'})
            f = urllib.urlopen(url, params)
            data = f.read().split()
            for line in data:
                domain = line.split('/')[0].strip()
                # if domain not in results:
                results.append(domain)

    return list(set(results))


def update_c2_feeds(sContext):
    sqlCtx = SQLContext(sContext)
    data = get_c2_feeds()
    rdd = sContext.parallelize(data)
    parsed_rdd = rdd.map(parser.Parser.parsec2)
    parsed_rdd.collect()
    df = parsed_rdd.toDF()
    df.save('reputation/c2', 'parquet', 'overwrite')
