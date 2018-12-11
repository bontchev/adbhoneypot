from __future__ import print_function
import os
import json
import MySQLdb
import logging
import time
import datetime
import calendar
import geoip2.database
import requests
import core.output
from core.config import CONFIG


class Output(core.output.Output):

    pass