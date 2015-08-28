from flask_nav.elements import (
    Navbar, View, Subgroup, Link, Text, Separator
)

from flask_nav import Nav

nav = Nav()

# We're adding a navbar as well through flask-navbar. In our example, the
# navbar has an usual amount of Link-Elements, more commonly you will have a
# lot more View instances.
nav.register_element('frontend_top', Navbar(
    View('BDSA', '.index'),
    View('Dashboard', '.index'),
    Subgroup(
        'Analytics',
        Text('VPN'),
        Separator(),
        Link('User stats', '/vpn/user'),
        Separator(),
        Text('Proxy'),
        Separator(),
        Link('Malware by user', '/proxy/malware/user'),
        Link('Top 10 Transfers', '/proxy/top/transfers'),
        Separator(),
        Text('Bash'),
        Separator(),
        Link('Keyword search', '/bash/keyword'),
    ),
    Subgroup(
        'Forensics',
        Link('Timeline analysis', '/search'),
    ),
    Subgroup(
        'Search',
        Link('Custom query', '/search'),
    ),

))
