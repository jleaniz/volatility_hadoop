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

from flask_nav.elements import (
    Navbar, View, Subgroup, Link, Text, Separator
)

from flask_nav import Nav

nav = Nav()

# We're adding a navbar as well through flask-navbar. In our example, the
# navbar has an usual amount of Link-Elements, more commonly you will have a
# lot more View instances.
nav.register_element('frontend_top', Navbar(
    View('BDSA', 'main.index'),
    View('Dashboard', 'dashboard.Dashboard'),
    Subgroup(
        'Analytics',
        Text('VPN'),
        Separator(),
        Link('User stats', '/vpn/user'),
        Separator(),
        Text('Proxy'),
        Separator(),
        Link('Endpoint malware search', '/proxy/endpoint'),
        Link('High data transfers', '/proxy/top/transfers'),
        Link('Most visited domains', '/proxy/top/visited'),
        Link('Most visited malware domains', '/proxy/top/malware'),
        Link('Most visited malware domains (OTX/C2)', '/proxy/top/malware/feeds'),
        Link('Uncommon User-Agents', '/proxy/uncommon/useragent'),
        Link('Outdated clients', '/proxy/endpoint/outdated'),
        Separator(),
        Text('Firewall'),
        Separator(),
        Link('Port stats', '/firewall/port/stats'),
        Link('IP stats', '/firewall/ip/stats'),
        Separator(),
        Text('Threat Intelligence'),
        Separator(),
        Link('Open Source feeds', '/intel/feeds/opensrc'),
        Link('AlienVault OTX', '/intel/feeds/otx'),
        Separator(),
        Text('Bash'),
        Separator(),
        Link('Keyword search', '/bash/keyword'),
    ),
    Subgroup(
        'Forensics',
        Link('Timeline analysis', '/forensics/timeline'),
    ),
    Subgroup(
        'ML Predictions',
        Link('Bashlog KMeans clusters', '/bash/kmeans'),
    ),
    Subgroup(
        'Search',
        Link('Custom query', '/search'),
    ),
    Subgroup(
        'Spark',
        Link('Clear cache', '/spark/clearcache'),
        Link('Cancel jobs', '/spark/canceljobs'),

    ),
))
