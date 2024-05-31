class BlockHtaccess:
    def __init__(self, blacklist):
        self.blacklist = blacklist
        print("BlockHtaccess loaded")
    
    def Run(self, ip):
        print(f"Add to file {self.blacklist}: '{ip} deny'")
        with open(self.blacklist, 'a') as out:
            out.write(f"{ip} deny\r\n")
