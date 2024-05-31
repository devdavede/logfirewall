import sys
import select
import logging
import os
from logging.handlers import RotatingFileHandler
from Analyzers.ResourceNotFoundAnalyzer import ResourceNotFoundAnalyzer
from Analyzers.MaliciousStringAnalyzer import MaliciousStringAnalyzer
from Protectors.BlockApache import BlockApache
from Protectors.BlockHtaccess import BlockHtaccess
from Logfirewall import Logfirewall

pathToAuditlog = "/home/ubuntu/firewall/auditlog.db"
pathToBlacklistedStrings = "/home/ubuntu/firewall/blacklisted_strings.txt"
pathToAccessLog = "/home/ubuntu/log/apache.access.log"
pathToErrorLog = "/home/ubuntu/firewall/dbg-out.txt"
pathToBlockHtaccess = "/var/www/blockedips.htaccess.conf"
pathToApacheBlacklist = "/home/ubuntu/firewall/ipblacklist.conf"

if __name__ == "__main__":
    logfirewall = Logfirewall(
        pathToAccessLog,
        [
            ResourceNotFoundAnalyzer(pathToAuditlog),
            MaliciousStringAnalyzer(pathToBlacklistedStrings)
        ],
        [
            BlockHtaccess(pathToBlockHtaccess),
            BlockApache(pathToApacheBlacklist)
        ]
    )

    logfirewall.Watch()