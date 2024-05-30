class BlockHtaccess:
    def __init__(self, blacklist):
        print("BlockHtaccess initialized")
        self.blacklist = blacklist
    
    def Run(self, ip):
        print(f"HTACCESS Blocking {ip}")
        with open(self.blacklist, 'a') as out:
            out.write(f"{ip} deny\r\n")