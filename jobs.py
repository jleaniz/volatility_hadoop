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
from pyspark.sql import SQLContext
from pyspark.sql.types import *
import threading

class SparkSQLJob(object):

    def __init__(self, sc, funcs):
        self.name = None
        self.sc = sc
        self.funcs = funcs
        self.funcArgs = []
        self.timers = []
        self.wait = 5.0

    def execute(self):
        for func in self.funcs:
            if func:
                if self.funcArgs:
                    self.timers.append( threading.Timer(self.wait, func, self.funcArgs) )

        for timer in self.timers:
            timer.start()

    def cancel(self):
        self.timer.cancel()
