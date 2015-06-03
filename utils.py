import tempfile
import os
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import mrjob.fs.hadoop
import re
from pyspark.sql import Row

class SparkVolatility:

    def __init__(self, volatilityModules):
        self.modules = volatilityModules

    def checkPathHadoop(self, hdfs_path):
        fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])
        try:
            fs.path_exists(hdfs_path)
            return True
        except:
            return False

    def rmHadoop(self, hdfs_path):
        fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])
        try:
            fs.rm(hdfs_path)
            return True
        except:
            return False

    def CopyHadoopLocal(self, hdfs_path, dest_path, img_name):
        # Read the image file from HDFS and write to /dev/shm
        fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])
        try:
            with open(dest_path + img_name, 'wb') as f:
                for line in fs.cat(hdfs_path + img_name):
                    f.write(line)
            f.close()
            return True
        except:
            return False

    def parseImageInfo(self, lines):
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
            profile = m_profile,
            kdbg = m_kdbg
            )
        

    def RunVolatility(self, modules, img_path):
        data = ""
        lines_strip = []

         # Volatility blackbox stuff
        registry.PluginImporter()
        config = conf.ConfObject()
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)

        # Set volatility memory image path
        config.LOCATION = img_path

        # Build volatility command and execute
        cmds = registry.get_plugin_classes(commands.Command, lower = True)
        for module in modules:
            command = cmds[module](config)
            data = command.calculate()

            # Store output in a temporary file and read it
            f = tempfile.NamedTemporaryFile(mode='w+',delete=True)
            command.render_text(f, data)
            f.seek(0)
            lines = f.readlines()
            f.close()

            # append the image name before the results
            lines_strip.append(img_path)

            # build a list with each value prefixed by the img path
            for i in lines:
                lines_strip.append(i.strip())

            if module == 'imageinfo':
                row = self.parseImageInfo(lines_strip)

        return row

    def Execute(self, img_path):
        if self.CopyHadoopLocal('hdfs:///user/cloudera/', '/dev/shm/', img_path):
            output = self.RunVolatility(self.modules, 'file:///dev/shm/' + img_path)
            os.remove('/dev/shm/' + img_path)
            return output #if this retunrs a tuple (key,value) we can use transformations in Pair RDDs




