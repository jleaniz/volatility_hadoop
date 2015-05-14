import os
import utils as utils
from mrjob.job import MRJob
import mrjob.protocol

#MRjob framework variables
INPUT_PROTOCOL = mrjob.protocol.RawValueProtocol
INTERNAL_PROTOCOL = mrjob.protocol.RawProtocol
OUTPUT_PROTOCOL = mrjob.protocol.RawProtocol

class MRPSlist(MRJob):

    def mapper(self, _, line):
        profile = ""
        kdbg = ""
        imgpath = line.strip()

        # Read the image file from HDFS and write to /dev/shm
        if utils.CopyHadoopLocal('hdfs:///user/cloudera/', '/dev/shm/', imgpath):

            data = utils.RunVolatility('pslist', 'file:///dev/shm/'+imgpath)

            # Emit key,value for each output line
            # (this is sent to the reducer function)
            for line in data:
                yield imgpath, line.strip()

            # Delete the temporary image copy
            os.remove('/dev/shm/'+imgpath)

    def reducer(self, key, values):
        for value in values:
            if value:           
                yield key, value

if __name__ == '__main__':
    MRPSlist.run()
