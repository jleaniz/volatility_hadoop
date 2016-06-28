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

import GeoIP

gi = GeoIP.open("GeoIP.dat",GeoIP.GEOIP_MEMORY_CACHE)

def getCountryCodeIP(gi, ipaddr):
    return gi.country_code_by_addr(ipaddr)

def getCountryCodeDomain(gi, domain):
    return gi.country_code_by_name(domain)