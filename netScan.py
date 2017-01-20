from multiprocessing import Pool, TimeoutError
import re,threading, sys
from urllib2 import urlopen
from urllib2 import URLError, HTTPError
from Queue import Queue as Q
import json, argparse
from scapy.all import *
# import logging
# log = logging.getLogger(__name__)
DOC = """
    this is scanner for local net.

    * scan ip:
        (1) ping to scan ip.
        (2) arp to get ip.
    * scan port:
        (1) syn to scan port.

    * scan dir:
        (1) to test weak http  uri.

"""

BLUE='\033[0;34m'
GREEN='\033[0;32m'
CYAN='\033[0;35m'
RED='\033[0;31m'
YELLOW='\033[0;36m'
NC='\033[0m'

default_setting = json.loads(open("scan.json").read())
conf.verb = 0

THREAD_COUNT = 0
FINISHED_THREAD_COUNT = 0

def finished_th():
    global FINISHED_THREAD_COUNT
    FINISHED_THREAD_COUNT += 1

def set_th_count(v):
    global FINISHED_THREAD_COUNT
    global THREAD_COUNT
    THREAD_COUNT = v
    FINISHED_THREAD_COUNT = 0

def get_ips(ip_template):
    base = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.', ip_template)[0]
    return [ base + str(i) for i in range(1,255)]

def get_ports(port_str):
    for ss in port_str.strip().split(","):
        if "-" in ss:
            for p in  range(int(ss.split("-")[0]), int(ss.split("-")[1]) +1):
                yield p
        else:
            yield int(ss)
            
        
 
class PortScan(threading.Thread):
    def __init__(self,queue, ip, ports, v=1):
        self.ip = ip
        self.ports = ports
        self.ip_p = IP(dst=ip) / TCP(sport=RandShort(), dport=self.ports,flags="S")
        self.queue = queue
        self.v = v
        super(PortScan, self).__init__()

    def Syn(self):
        s,_ = sr(self.ip_p, timeout=2,inter=0.1)
        # filter results
        return s.filter(lambda (s,r):r.sprintf("%TCP.flags%") == "SA" )


    def run(self):
        if self.v > 0:
            sys.stdout.write("start:" + GREEN + self.name + NC + "\r")
            sys.stdout.flush()
        s,_ = sr(self.ip_p, timeout=2,inter=0.1)
        ss = s.filter(lambda (s,r):r.sprintf("%TCP.flags%") == "SA" )
        results = []
        for s in ss:
            results.append(s[1].src + "," + str(s[1].sport))

        self.queue.put(results)
        finished_th()
        if self.v > 0:
            
            sys.stdout.write("End:" + GREEN + str(FINISHED_THREAD_COUNT) +"/" + str(THREAD_COUNT) + NC + "         \r")
            sys.stdout.flush()


class IpScan(threading.Thread):
    def __init__(self,  queue,ips,type="arp",v = 1):
        self.ips = ips
        self.queue = queue
        self.type = type
        self.v = v
        super(IpScan, self).__init__()

    def run(self):
        if self.v > 0:
            sys.stdout.write("start:" + GREEN + self.name + NC + "\r")
            sys.stdout.flush()
        if self.type == "arp":
            s,_ =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ ARP(op=1, pdst=self.ips), timeout=1,inter=0.1)
            alive = [i[0].pdst  for i in  s]
        elif self.type == "ping":
            s,_ =  sr(IP(dst=self.ips)/ ICMP(), timeout=1,inter=0.1)
            alive = [i[0].dst   for i in  s]
        self.queue.put(alive)

        finished_th()
        if self.v > 0:
            sys.stdout.write("End:" + GREEN + str(FINISHED_THREAD_COUNT) +"/" + str(THREAD_COUNT) + NC + "         \r")
            sys.stdout.flush()



class Test(threading.Thread):

    def __init__(self, ips, pro):
        self.resource = ips
        self.type = pro
        super(Sni, self).__init__()

    def run(self):
        for url in self.resource:
            try:
                urlopen(url)
            except URLError,e:
                if e.code == 111:
                    print("web server is:" + RED+ "down" + NC)
                break
            except HTTPError,e:
                print(e.code + "," + url)


def ip_scan(ip,th=12,check=2, pro_type="arp"):
    print(BLUE + "[Ip scan]" + NC)
    set_th_count(th)
    ips = get_ips(ip)
    c = int(len(ips) / th)
    threads = []
    q = Q()
    alive = set()
    for i in range(check):
        for i in range(th+1):
            tm_ips = ips[i*c :i * c+c]
            t = IpScan(q, tm_ips, type=pro_type)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        results = []
        for i in range(th):
            results += (q.get())

        alive = alive | set(results)
        if pro_type == "ping" and i != 0:
            break
        set_th_count(th)

    return list(alive)

def port_scan(ips, ports, th=12, check = 2):
    set_th_count(th)
    c = int(len(ports) / th)
    print(BLUE + "[Port scan]" + NC)
    threads = []
    q = Q()
    alive = dict()
    values = set()
    for iii in range(check):
        for i in range(th+1):
            tm_ports = ports[i*c :i * c+c]
            t = PortScan(q, ips, tm_ports)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        for i in range(th):
            # try:
            values |= set(q.get())
        set_th_count(th)

    for value in values:
        t,v = value.split(",")
        old = alive.get(t,[])
        old.append(v)
        alive[t] = old
        # except Empty,e:
            # pass

    return alive

def local_test(ip):
    return port_scan(ip_scan(ip) , default_setting[u'scan_ports'])

def args():
    parser = argparse.ArgumentParser(usage=" how to use this", description=DOC)
    
    
    
    parser.add_argument("target", help="the target ip [CIRC].")
    parser.add_argument("-i","--ip-scan",default=False, action='store_true', help="delete Module in py file.")
 
    parser.add_argument("-p","--port-scan", default=None, help="set port, exp: 21-25,80,443 , if none will use scan.json")
    parser.add_argument("-L","--local-scan", default=False, action='store_true', help="scan local ip then to scan ports.")
    parser.add_argument("-it","--ip-scan-type", default="arp", help="set ip scan's type default is arp, exp: -it ping")
    parser.add_argument("-T", "--thread", default=6, type=int, help="set threads' number.")
    parser.add_argument("-l", "--load", default=False, action='store_true', help="load local's. [target].save dir")
    parser.add_argument("-v", "--verbose", default=0, type=int, help="set log's level.")
    return parser.parse_args()

def display(res, f,t="ip"):
    if t == "ip":
        with open(f, "w") as f:
            for r in res:
                print(r + " "+ GREEN + "up" + NC)
                f.write(r+"\n")

    elif t == "port":
        with open(f, "w") as f:
            for k in res:
                print(YELLOW + k + NC + " "+ GREEN + "\n\t"+'\n\t'.join([str(i) for i in res[k]]) + NC)
            f.write(json.dumps(res))

def main():
    ag = args()
    set_th_count(ag.thread)
    auto_save = ag.target + ".save"
    ip_file = os.path.join(auto_save,"ip")
    port_file = os.path.join(auto_save,"port")
    try:
        os.mkdir(auto_save)
    except Exception:
        pass
    conf.verb = ag.verbose
    if ag.local_scan:
        ports = list(get_ports(ag.port_scan))
        res = port_scan(ip_scan(ag.target, pro_type=ag.ip_scan_type), ports,th=ag.thread)
        display(res, port_file,"port")

        
    elif ag.port_scan:
        ports = list(get_ports(ag.port_scan))
        if ag.load and os.path.exists(ip_file):
            ips = open(ip_file).read().split("\n")
            res = port_scan(ips, ports,th=ag.thread)
        else:
            res = port_scan(ag.target, ports,th=ag.thread)
        display(res, port_file,"port")

    elif ag.ip_scan:
        res = ip_scan(ag.target,th=ag.thread, pro_type=ag.ip_scan_type)
        display(res,ip_file) 

if __name__ == '__main__':
    main()