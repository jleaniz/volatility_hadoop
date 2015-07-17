from setuptools import setup

setup(
    name='bdsa',
    version='0.1-alpha',
    packages=['lib', 'config', 'ingest', 'ingest.apache', 'ingest.bluecoat', 'ingest.bluecoat.apache',
              'ingest.firewall', 'ingest.intelfeeds', 'ingest.volatility', 'brainiac', 'analytics',
              'analytics.bluecoat', 'analytics.iptables'],
    url='http://jleaniz.github.io/bdsa/',
    license='GNU Lesser General Public License version 3',
    author='Juan Leaniz',
    author_email='juan.leaniz@gmail.com',
    description='Big Data Security Analytics'
)
