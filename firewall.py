# logfirewall.py
import sys
import select
import logging
from logging.handlers import RotatingFileHandler
from Analyzers.ResourceNotFoundAnalyzer import ResourceNotFoundAnalyzer
from Analyzers.MaliciousStringAnalyzer import MaliciousStringAnalyzer
from Protectors.BlockApache import BlockApache
from Protectors.BlockHtaccess import BlockHtaccess

class Logfirewall:
    def __init__(self, logfile, analyzers, protectors):
        self.analyzers = analyzers
        self.protectors = protectors
        self.logfile = logfile
        self.initLogger()

    def initLogger(self):
        self.logger = logging.getLogger("ApacheErrorLogAnalyzer")
        self.logger.setLevel(logging.INFO)
        self.handler = RotatingFileHandler(self.logfile, maxBytes=10*1024*1024, backupCount=5)
        self.formatter = logging.Formatter('%(asctime)s - %(message)s')
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)
    
    def Analyze(self, line):
        for analyzer in self.analyzers:
            isAttacker, ip = analyzer.Analyze(line)
            if isAttacker:
                for protector in self.protectors:
                    protector.Run(ip)

    def Watch(self):
        while True:
            while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:
                    self.Analyze(line)
                    self.logger.info(line)

if __name__ == "__main__":
    logfirewall = Logfirewall(
        "/home/ubuntu/log/apache.access.log",
        [
            ResourceNotFoundAnalyzer("auditlog.db"),
            MaliciousStringAnalyzer("/home/ubuntu/firewall/blacklisted_strings.txt")
        ],
        [
            BlockHtaccess("/var/www/blockedips.htaccess.conf"),
            BlockApache("/home/ubuntu/firewall/ipblacklist.conf")
        ]
    )
    
    if len(sys.argv) > 1 and sys.argv[1] == "1":
        line = "[Mon May 27 05:38:39.590010 2024] [php:error] [pid 8112] [client 91.92.252.171:65223] script '/var/www/html/wso.php /var/www/html/404.php' not found or unable to stat"
        logfirewall.Analyze(line)
    else:
        logfirewall.Watch()
