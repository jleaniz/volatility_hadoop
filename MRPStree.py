import tempfile
import os
import shlex
import subprocess
import mrjob.fs.hadoop
from mrjob.job import MRJob
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.pstree as pstree

INPUT_PROTOCOL = mrjob.protocol.RawValueProtocol
INTERNAL_PROTOCOL = mrjob.protocol.RawProtocol
OUTPUT_PROTOCOL = mrjob.protocol.RawProtocol

class MRImageInfo(MRJob):

    def mapper(self, _, line):
		profile = ""
		kdbg = ""
		imgpath = line.strip()

		fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])

		with open('/dev/shm/' + imgpath, 'wb') as f:
			for line in fs.cat('hdfs:///user/cloudera/' + imgpath):
				f.write(line)
		f.close

		registry.PluginImporter()
		config = conf.ConfObject()
		registry.register_global_options(config, commands.Command)
		registry.register_global_options(config, addrspace.BaseAddressSpace)
		config.LOCATION = "file:///dev/shm/" + imgpath

		cmds = registry.get_plugin_classes(commands.Command, lower = True)
		command = cmds['pslist'](config)
		data = command.calculate()

		f = tempfile.NamedTemporaryFile(mode='w+',delete=True)
		command.render_text(f, data)
		f.seek(0)
		lines = f.readlines()

		for line in lines:
			yield imgpath, line.strip()
		f.close()

		os.remove('/dev/shm/'+imgpath)

#    def reducer(self, key, values):
#	for value in values:
#		if value:			
#			yield key, value

if __name__ == '__main__':
	MRImageInfo.run()
