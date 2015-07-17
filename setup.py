#
# This file is part of BDSA (Big Data Security Analytics)
#
# Foobar is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Foobar is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#
from setuptools import setup

setup(
    name='bdsa',
    version='0.1-alpha',
    packages=['lib', 'config', 'ingest', 'ingest.apache', 'ingest.bluecoat',
              'ingest.firewall', 'ingest.intelfeeds', 'ingest.volatility', 'brainiac', 'analytics',
              'analytics.bluecoat', 'analytics.iptables'],
    url='http://jleaniz.github.io/bdsa/',
    license='GNU Lesser General Public License version 3',
    author='Juan Leaniz',
    author_email='juan.leaniz@gmail.com',
    description='Big Data Security Analytics'
)
