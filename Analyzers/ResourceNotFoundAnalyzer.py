import sqlite3
from datetime import datetime, timedelta
import re
import logging
import logging.handlers


class ResourceNotFoundAnalyzer:
    def __init__(self, dbPath):
        self.Name = "ResourceNotFoundAnalyzer"
        self.conn = sqlite3.connect(dbPath)
        self.cursor = self.conn.cursor()
        self.logPattern = r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<datetime>[^\]]+)] "(?:GET|POST) (?P<url>\S+) HTTP/[^"]+" (?P<status>\d{3}) (?P<size>\d+) "[^"]*" "(?P<browser>[^"]+)"'
        self.InitTables()
    
    def InitTables(self):
        self.cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS auditlog (
            id INTEGER PRIMARY KEY,
            message TEXT NOT NULL,
            ip TEXT NOT NULL,
            risklevel INTEGER NOT NULL,
            timestamp DATETIME DEFAULT (DATETIME('now', 'localtime'))
            )
            ''')

    def AddToAuditLog(self, ip, message, risklevel):
        self.cursor.execute('INSERT INTO auditlog (message, ip, risklevel) VALUES (?, ?, ?)', (message, ip, risklevel))
        self.conn.commit()

    def CheckLimits(self, ip):
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        self.cursor.execute('SELECT * FROM auditlog WHERE ip = ? AND timestamp >= ?', (ip, one_minute_ago,))
        entries = self.cursor.fetchall()
        if len(entries) > 5: return True, ip
        return False, ip

    def CheckSuspicious(self, ip, message, risklevel):
        self.AddToAuditLog(ip, message, risklevel)
        return self.CheckLimits(ip)

    def checkAccessLog(self, timestamp, log_level, ip, status, message):
        if "not found or unable to stat" in message: return self.CheckSuspicious(ip, message, 1)
        if status == "404": return self.CheckSuspicious(ip, message, 1)
        return False, ip

    def Analyze(self, logline):
        match = re.search(self.logPattern, logline)
        if match:
            ip = match.group('ip')
            timestamp = match.group('datetime')
            url = match.group('url')
            status = match.group('status')
            size = match.group('size')
            browser = match.group('browser')
            return self.checkAccessLog(timestamp, 1, ip, status, logline)
        return False, None
