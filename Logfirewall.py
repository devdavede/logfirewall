import logging
import sys
from logging.handlers import RotatingFileHandler
import select

class Logfirewall:
    def __init__(self, logfile, analyzers, protectors):
        self.analyzers = analyzers
        self.protectors = protectors
        self.logfile = logfile
        self.logQueue = []
        self.initLogger()

    def initLogger(self):
        self.logger = logging.getLogger("ApacheErrorLogAnalyzer")
        self.logger.setLevel(logging.INFO)
        self.handler = RotatingFileHandler(self.logfile, maxBytes=10*1024*1024, backupCount=5)
        self.formatter = logging.Formatter('%(asctime)s - %(message)s')
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)
    
    def Analyze(self, line):
        print(f"Analyze: {line}")
        for analyzer in self.analyzers:
            isAttacker, ip = analyzer.Analyze(line)
            if isAttacker:
                for protector in self.protectors:
                    protector.Run(ip)
    
    def Inject(self, line):
        self.logQueue.append(line) 

    def Watch(self):
        while True:
            while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:
                    self.Analyze(line)
                    self.logger.info(line)