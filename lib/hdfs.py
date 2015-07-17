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
import mrjob.fs.hadoop


def checkPathHadoop(hdfs_path):
    fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])
    try:
        fs.path_exists(hdfs_path)
        return True
    except:
        return False


def rmHadoop(hdfs_path):
    fs = mrjob.fs.hadoop.HadoopFilesystem(['hadoop'])
    try:
        fs.rm(hdfs_path)
        return True
    except:
        return False


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
