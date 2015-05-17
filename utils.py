import tempfile
import os
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import mrjob.fs.hadoop

class SparkVolatility:

    def __init__(self, volatilityModules):
        self.modules = volatilityModules

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

    def RunVolatility(self, module, img_path):
         # Volatility blackbox stuff
        registry.PluginImporter()
        config = conf.ConfObject()
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)

        # Set volatility memory image path
        config.LOCATION = img_path

        # Build volatility command and execute
        cmds = registry.get_plugin_classes(commands.Command, lower = True)
        command = cmds[module](config)
        data = command.calculate()

        # Store output in a temporary file and read it
        f = tempfile.NamedTemporaryFile(mode='w+',delete=True)
        command.render_text(f, data)
        f.seek(0)
        lines_strip = []
        lines = f.readlines()
        for i in lines:
            lines_strip.append(img_path+':'+i.strip())

        f.close()
        return lines_strip

    def ImageInfo(self, img_path):
        if self.CopyHadoopLocal('hdfs:///user/cloudera/', '/dev/shm/', img_path):
            output = self.RunVolatility('imageinfo', 'file:///dev/shm/' + img_path)
            os.remove('/dev/shm/' + img_path)
            return output #if this retunrs a tuple (key,value) we can use transformations in Pair RDDs

    def parseImageInfo(self, ImageInfoOutput):
        parsedOutput = []
        for lines in ImageInfoOutput:
            for line in lines:
                if len(line.split(':')) == 4:
                    (prefix, img_path, key, value) = line.split(':')
                    if 'KDBG' in key:
    #                    print "%s:%s:%s" % (img_path, key, value)
                        # this will need rework if ImageInfo returns a tuple (key, vlue)
                        kdbg = "%s:%s:%s" % (img_path, key, value)
                        parsedOutput.append(kdbg)
        return parsedOutput
