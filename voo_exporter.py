import time
import requests
from bs4 import BeautifulSoup
import hashlib
from prometheus_client.core import REGISTRY, GaugeMetricFamily, CounterMetricFamily
from prometheus_client import start_http_server
import re
from config import *

TABLE_STATS = 0
TABLE_DS_LEVELS = 1
TABLE_US_LEVELS = 2
TABLE_IP_LEASE = 3

DS_CHAN_NUM = 16
US_CHAN_NUM = 4

class VooCollector:
    """
    Collects signal and system info about VOO cable modem and exports them as Prometheus metrics
    Tested with model TC7210
    """
    def __init__(self):
        pass

    def fail(self):
        return GaugeMetricFamily("voo_up", "VOO CM Status", value=0)

    def _get_csrf_token(self):
        try:
            init_req = requests.get(f"http://{CM_IP}/", timeout=HTTP_TIMEOUT)
        except Exception as ex:
            print(f"Failed acquiring CSRF Token : {str(ex)}")
            return None
        if not init_req.ok:
            return None
        init_soup = BeautifulSoup(init_req.content, "html.parser")
        csrf_token = init_soup.find("input", {"name":"CSRFValue"}).get('value')
        return csrf_token

    def _auth(self):
        csrf_token = self._get_csrf_token()
        pass_hash = hashlib.sha256(CM_PASS.encode("utf-8")).hexdigest()
        payload = {
            "CSRFValue": csrf_token,
            "loginUsername": CM_USER, 
            "loginPassword": pass_hash, 
            "logoffUser": "0"
            }
        try:
            auth_req = requests.post(f"http://{CM_IP}/goform/login", data=payload, timeout=HTTP_TIMEOUT)
        except Exception as ex:
            print(f"Failed logging in : {str(ex)}")
            return False
        if not auth_req.ok:
            return False
        return True

    def fetch_swinfo(self):
        #Get status
        try:
            swinfo_req = requests.get(f"http://{CM_IP}/RgSwInfo.asp", timeout=HTTP_TIMEOUT)
        except Exception as ex:
            print(f"Failed acquiring Swinfo : {str(ex)}")
            return None
        if not swinfo_req.ok:
            return None
        return swinfo_req

    def collect(self):
        # Try to get the software info page anyway. We will receive a login form if we need to authenticate
        swinfo_req = self.fetch_swinfo()
        if not swinfo_req:
            yield self.fail()
            return

        swinfo_soup = BeautifulSoup(swinfo_req.content, "html.parser")
        loginform = swinfo_soup.find("form", {"name": "login"})

        if loginform:
            ret = self._auth()     
            if not ret:
                yield self.fail()
                return

            swinfo_req = self.fetch_swinfo()
            if not swinfo_req:
                yield self.fail()
                return
            
            swinfo_soup = BeautifulSoup(swinfo_req.content, "html.parser")
            loginform = swinfo_soup.find("form", {"name": "login"})
            #If we still get a login form then our credentials are probably wrong.
            if loginform: 
                yield self.fail()
                return
                
        # We receive a page with two tables
        # - Information about the modem itself (hw/sw/fw)
        # - Uptime + CM IP Address
        swinfo_tables = swinfo_soup.findAll("table")
        infos1 = swinfo_tables[1].findAll("td")
        sw_version = infos1[6].text
        mac_address = infos1[8].text
        serial_number = infos1[10].text
        
        infos2 = swinfo_tables[2].findAll("td")
        uptime = infos2[2].text
        # 0  05h:35m:02s
        seconds = 0
        match = re.match(r"\s?(?P<days>\d+)\s+(?P<hours>\d+)h:(?P<minutes>\d+)m:(?P<seconds>\d+)s",uptime)
        if match:
            groups = match.groupdict()
            seconds = int(groups["seconds"])
            seconds += int(groups["minutes"])*60
            seconds += int(groups["hours"])*3600
            seconds += int(groups["days"])*86400

        counter_status = CounterMetricFamily(f"voo_up", "VOO CM Status", labels=["version", "mac_address", "serial_number"])
        counter_status.add_metric([sw_version, mac_address, serial_number], seconds)
        yield counter_status


        #Fetch levels. 
        try:
            levels_req = requests.get(f"http://{CM_IP}/RgConnect.asp", timeout=HTTP_TIMEOUT)
        except Exception as ex:
            print(f"Failed acquiring levels : {str(ex)}")
            yield self.fail()
            return
        if not levels_req.ok:
            yield self.fail()
            return

        levels_soup = BeautifulSoup(levels_req.content, "html.parser")
        main_table = levels_soup.find("table")
        tables = main_table.find_all("table")
        idx = 0

        #We receive a page with 4 tables :
        # - Startup procedure
        # - Downstream channels
        # - Upstream channels
        # - CM ip address (WAN ip assigned to the customer. Not populated when in bridge mode)
        for idx in range(0,len(tables)):
            table = tables[idx]
            if idx == TABLE_STATS or idx == TABLE_IP_LEASE:
                continue
            if idx == TABLE_DS_LEVELS:
                lvls = table.find_all("tr")
                for lvl in lvls[2:]:
                    lvl_infos = lvl.find_all("td")
                    channel_id = int(lvl_infos[0].text)

                    channel_power = float(lvl_infos[6].text.strip().split(" ")[0])
                    gauge_power = GaugeMetricFamily(f"voo_downstream_channel_{channel_id}_power", f"Downstream Channel {channel_id} Received Power", channel_power)
                    
                    channel_snr = float(lvl_infos[7].text.strip().split(" ")[0])
                    gauge_snr = GaugeMetricFamily(f"voo_downstream_channel_{channel_id}_snr", f"Downstream Channel {channel_id} SNR", channel_snr)

                    yield gauge_snr
                    yield gauge_power
                    
            if idx == TABLE_US_LEVELS:
                lvls = table.find_all("tr")
                for lvl in lvls[2:]:
                    lvl_infos = lvl.find_all("td")
                    channel_id = int(lvl_infos[0].text)
                    channel_power = float(lvl_infos[6].text.strip().split(" ")[0])
                    gauge_power = GaugeMetricFamily(f"voo_upstream_channel_{channel_id}_power", f"Upstream Channel {channel_id} Sent Power", channel_power)

                    yield gauge_power

    def describe(self):
        for idx in range(DS_CHAN_NUM):
            counter_status = CounterMetricFamily(f"voo_up", "VOO CM Status", labels=["version", "mac_address", "serial_number"])
            yield counter_status

            gauge_power = GaugeMetricFamily(f"voo_downstream_channel_{idx}_power", f"Downstream Channel {idx} Received Power")
            gauge_snr = GaugeMetricFamily(f"voo_downstream_channel_{idx}_snr", f"Downstream Channel {idx} SNR")
            yield gauge_snr
            yield gauge_power

            gauge_power = GaugeMetricFamily(f"voo_upstream_channel_{idx}_power", f"Upstream Channel {idx} Sent Power")
            yield gauge_power


def main():
    REGISTRY.register(VooCollector())
    start_http_server(LISTEN_PORT)
    while True:
        time.sleep(10)




if __name__ == "__main__":
    main()

