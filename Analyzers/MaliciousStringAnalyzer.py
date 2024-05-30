import re

class MaliciousStringAnalyzer:
    def __init__(self, blacklistedStringsPath):
        self.ReadMaliciousStrings(blacklistedStringsPath)
        self.logPattern = re.compile(r'^\[(.*?)\] \[(.*?)\] \[pid (.*?)\] \[client (.*?)\] (.*)')

    def ReadMaliciousStrings(self, blacklistedStringsPath):
        stringFile = open(blacklistedStringsPath, 'r')
        self.blacklistedStrings = stringFile.readlines()
        stringFile.close()
    
    def containsSubstring(self, string, substrings):
        for substring in substrings:
            if substring.strip() in string:
                return True
        return False

    def Analyze(self, logline):
        match = self.logPattern.match(logline)
        if match:
            timestamp, log_level, pid, ip, message = match.groups()
            if self.containsSubstring(logline, self.blacklistedStrings):
                return True, ip
        return False, False
