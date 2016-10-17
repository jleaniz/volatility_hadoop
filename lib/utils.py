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
import tempfile
import os

import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import bdsa.lib.parser as parser
import bdsa.lib.hdfs as hdfs
from pyspark.sql.types import *
from pyspark.sql import Row


class SparkVolatility:
    def __init__(self, volatilityModules):
        self.module = volatilityModules
        self.kdbg = ''
        self.profile = ''

    def RunVolatility(self, img_path):
        data = ""
        lines_strip = []
        row = Row(image='', kdbg='', profile='')

        # Volatility blackbox stuff
        registry.PluginImporter()
        config = conf.ConfObject()
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)
        config.parse_options()

        # Set volatility memory image path
        config.LOCATION = img_path
        if self.module != 'imageinfo':
            config.PROFILE = self.profile

        # Build volatility command and execute
        cmds = registry.get_plugin_classes(commands.Command, lower=True)
        command = cmds[self.module](config)
        data = command.calculate()

        # Store output in a temporary file and read it
        f = tempfile.NamedTemporaryFile(mode='w+', delete=True)
        command.render_text(f, data)
        f.seek(0)
        lines = f.readlines()
        f.close()

        # Only need to keep the local fs path
        img_path = img_path.split('/')[5]

        # build a list with each value prefixed by the img path
        for i in lines:
            lines_strip.append(i.strip())

        if self.module == 'imageinfo':
            row = parser.parseImageInfo(img_path, lines_strip)

        if self.module == 'pslist':
            row = parser.parsePSList(img_path, lines_strip)

        return row  # this breaks the loop

    def Execute(self, data):
        if self.module == 'imageinfo':
            # in this case, data is actually just a string with the image path
            if hdfs.CopyHadoopLocal('hdfs:///user/cloudera/', '/dev/shm/', data):
                output = self.RunVolatility('file:///dev/shm/' + data)
                os.remove('/dev/shm/' + data)
                return output  # if this retunrs a tuple (key,value) we can use transformations in Pair RDDs
        else:
            # here data is each row in a dataframe that contains name, kdbg and profile
            if hdfs.CopyHadoopLocal('hdfs:///user/cloudera/', '/dev/shm/', data.image):
                self.kdbg = data.kdbg
                self.profile = data.profile
                output = self.RunVolatility('file:///dev/shm/' + data.image)
                os.remove('/dev/shm/' + data.image)
                return output  # if this retunrs a tuple (key,value) we can use transformations in Pair RDDs