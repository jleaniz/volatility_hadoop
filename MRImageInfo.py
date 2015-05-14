import os
import shlex
import subprocess
import mrjob.fs.hadoop
from mrjob.job import MRJob
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.imageinfo as imageinfo

INPUT_PROTOCOL = mrjob.protocol.RawValueProtocol
INTERNAL_PROTOCOL = mrjob.protocol.RawProtocol
OUTPUT_PROTOCOL = mrjob.protocol.RawProtocol

class MRImageInfo(MRJob):

    def mapper(self, _, line):
		profile = ""
		kdbg = ""
		imgpath = line.strip()

		# Read the image file from HDFS and write to /dev/shm
		fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])
		with open('/dev/shm/' + imgpath, 'wb') as f:
			for line in fs.cat('hdfs:///user/cloudera/' + imgpath):
				f.write(line)
		f.close

		# Volatility blackbox stuff
		registry.PluginImporter()
		config = conf.ConfObject()
		registry.register_global_options(config, commands.Command)
		registry.register_global_options(config, addrspace.BaseAddressSpace)
	
		# Set volatility memory image path
		config.LOCATION = "file:///dev/shm/" + imgpath 

		# Rrun volatility ImageInfo
		p = imageinfo.ImageInfo(config)
		# emit key,value for each line of output
		for i in p.calculate():
			if i:
				try:
#					conv = (str(x) for x in i)
#					value = ''.join(conv).strip()
					yield imgpath, i
				except:
					pass

		os.remove('/dev/shm/'+imgpath)

    def reducer(self, key, values):
	for value in values:
		if value:			
			yield key, value

if __name__ == '__main__':
	MRImageInfo.run()
