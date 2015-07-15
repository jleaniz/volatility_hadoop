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
