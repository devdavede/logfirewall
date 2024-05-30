class BlockApache:
    def __init__(self, blacklist):
        self.blacklist = blacklist
        print("BlockApache initialized")
    
    def Run(self, ip):
        print(f"Apache Blocking {ip}")
        with open(self.blacklist, 'a') as out:
            out.write(f"Require not ip {ip}\r\n")
