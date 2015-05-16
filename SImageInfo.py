import utils
from pyspark import SparkContext

if __name__ == '__main__':
    '''
    If you can package your module into a .egg or .zip file, you should be able to list it in pyFiles when constructing your SparkContext (or you can add it later through
    sc.addPyFile).
    For Python libraries that use setuptools, you can run python setup.py bdist_egg to build an egg distribution.
    Another option is to install the library cluster-wide, either by using pip/easy_install on each machine or by sharing a Python installation over a cluster-wide
    filesystem (like NFS).
    '''
    sc = SparkContext("local", "SparkVolatility", pyFiles=['utils.py'])
    images = sc.textFile('/user/cloudera/imgnames.txt')

    modules = ['imageinfo']
    volatility = utils.SparkVolatility(modules)

    if 'imageinfo' in volatility.modules:
        rdd = images.map(volatility.ImageInfo)
        volatilityOutput = rdd.collect()
        for i in volatility.parseImageInfo(volatilityOutput):
            print i

    #rdd = images.map(utils.ImageInfo)
    sc.stop()