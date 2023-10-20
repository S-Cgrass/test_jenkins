from __future__ import absolute_import, division, print_function, unicode_literals

import os
from socket import timeout
import sys

import json
import requests
import datetime

now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
now_str=str(now)
# content1="test message"+ now
content2="testmessage" + now_str
print(now)
print(now_str)
print(content2)
print(now)
print(now_str)
print(content2)
# print(now)
# print(now_str)
# print(content2)

