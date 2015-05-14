import tempfile
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import mrjob.fs.hadoop

def CopyHadoopLocal(hdfs_path, dest_path, img_name):
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

def RunVolatility(module, img_path):
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
    lines = f.readlines()

    return lines
