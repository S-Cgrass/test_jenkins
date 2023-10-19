from __future__ import absolute_import, division, print_function, unicode_literals

import os
from socket import timeout
import sys

# splunkhome = os.environ['SPLUNK_HOME']
sys.path.append(os.path.join('D:\splunk\splunk 8.2.3', 'etc', 'apps', 'splunk_app_for_threatbook', 'lib'))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import six

import json
import requests

### add a annotation for test jenkins

### add a annotation for test jenkins


### add a annotation for test jenkins



@Configuration()
class TipCommand(StreamingCommand):
    key = Option(name='key', require=True)
    type = Option(name='type', require=True)
    field = Option(name='field', require=True)

    def stream(self, records):
        # ip
        if self.type == "ip":
            ip_url = "https://api.threatbook.cn/v3/scene/ip_reputation"
            for record in records:
                query = {"apikey": self.key, "resource": record[self.field]}
                try:
                    response = requests.request("GET", url=ip_url, params=query, timeout=5)
                    results = response.json()
                    self.logger.debug(results)
                    if results["response_code"] == 0:
                        for zz in results["data"]:
                            # is_malicious
                            if results["data"][zz]['is_malicious']:
                                record["is_malicious"] = "Yes"
                            else:
                                record["is_malicious"] = "No"
                            record["judgments"] = results["data"][zz]["judgments"]
                            record["response_code"] = results["response_code"]
                            record["verbose_msg"] = results["verbose_msg"]
                            record["carrier"] = results["data"][zz]["basic"]["carrier"]
                            record["city"] = results["data"][zz]["basic"]["location"]["city"]
                            record["country"] = results["data"][zz]["basic"]["location"]["country"]
                            record["country_code"] = results["data"][zz]["basic"]["location"]["country_code"]
                            record["lat"] = results["data"][zz]["basic"]["location"]["lat"]
                            record["lng"] = results["data"][zz]["basic"]["location"]["lng"]
                            record["province"] = results["data"][zz]["basic"]["location"]["province"]
                            record["severity"] = results["data"][zz]["severity"]
                            if results["data"][zz]["tags_classes"]:
                                record["tags"] = results["data"][zz]["tags_classes"]
                            else:
                                record["tags"] = "null"
                            record["update_time"] = results["data"][zz]["update_time"]
                            self.logger.debug(record)
                            yield record
                    else:
                        record["response_code"] = results["response_code"]
                        record["verbose_msg"] = results["verbose_msg"]
                        yield record
                except Exception as e:
                    record["response_code"] = "-1"
                    record["verbose_msg"] = "ERROR:访问<" + ip_url + "> url 超时!请检查网络.详细内容:" + str(e)
                    yield record

        # domain
        if self.type == "domain":
            ip_url = "https://api.threatbook.cn/v3/domain/query"
            for record in records:
                query = {"apikey": self.key, "resource": record[self.field]}
                try:
                    response = requests.request("GET", url=ip_url, params=query, timeout=5)
                    results = response.json()
                    self.logger.debug(results)
                    if results["response_code"] == 0:
                        for zz in results["data"]:
                            # is_malicious
                            if results["data"][zz]['is_malicious']:
                                record["is_malicious"] = "Yes"
                            else:
                                record["is_malicious"] = "No"
                            record["judgments"] = results["data"][zz]["judgments"]
                            record["response_code"] = results["response_code"]
                            record["verbose_msg"] = results["verbose_msg"]
                            for zzz in  results["data"][zz]["cur_ips"]:
                                record["ip"] = results["data"][zz]["cur_ips"][zzz]["ip"]
                                record["carrier"] = results["data"][zz]["cur_ips"][zzz]["carrier"]
                                record["city"] = results["data"][zz]["cur_ips"][zzz]["location"]["city"]
                                record["country"] = results["data"][zz]["cur_ips"][zzz]["location"]["country"]
                                record["country_code"] = results["data"][zz]["cur_ips"][zzz]["location"]["country_code"]
                                record["province"] = results["data"][zz]["cur_ips"]["location"]["province"]
                            record["confidence"] = results["data"][zz]["intelligences"]["threatbook_lab"]["confidence"]
                            record["find_time"] = results["data"][zz]["intelligences"]["threatbook_lab"]["find_time"]
                            record["intel_types"] = results["data"][zz]["intelligences"]["threatbook_lab"]["intel_types"]
                            if results["data"][zz]["tags_classes"]:
                                record["tags"] = results["data"][zz]["tags_classes"]
                            else:
                                record["tags"] = "null"
                            self.logger.debug(record)
                            yield record
                    else:
                        record["response_code"] = results["response_code"]
                        record["verbose_msg"] = results["verbose_msg"]
                        yield record
                except Exception as e:
                    record["response_code"] = "-1"
                    record["verbose_msg"] = "ERROR:访问<" + ip_url + "> url 超时!请检查网络.详细内容:" + str(e)
                    yield record

        # #  file/hash
        # if self.type == "file":
        #     ip_url = "https://api.threatbook.cn/v3/file/upload"
        #     for record in records:
        #         query = {"apikey": self.key, "file": record[self.field]}
        #         try:
        #             response = requests.request("GET", url=ip_url, params=query, timeout=5)
        #             results = response.json()
        #             self.logger.debug(results)
        #             if results["response_code"] == 0:
        #                 for zz in results["data"]:
        #                     record["response_code"] = results["response_code"]
        #                     record["verbose_msg"] = results["verbose_msg"]
        #                     record["sha256"] = results["data"][zz]["sha256"]
        #                     record["permalink"] = results["data"][zz]["permalink"]
        #                     self.logger.debug(record)
        #                     yield record
        #             else:
        #                 record["response_code"] = results["response_code"]
        #                 record["verbose_msg"] = results["verbose_msg"]
        #                 yield record
        #         except Exception as e:
        #             record["response_code"] = "-1"
        #             record["verbose_msg"] = "ERROR:访问<" + ip_url + "> url 超时!请检查网络.详细内容:" + str(e)
        #             yield record

dispatch(TipCommand, sys.argv, sys.stdin, sys.stdout, __name__)
