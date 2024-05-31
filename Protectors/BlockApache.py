class BlockApache:
    def __init__(self, blacklist):
        self.blacklist = blacklist
        print("BlockApache loaded")

    def Run(self, ip):
        print(f"Add to file {self.blacklist}: '{ip} deny'")
        with open(self.blacklist, 'a') as out:
            out.write(f"Require not ip {ip}\r\n")
