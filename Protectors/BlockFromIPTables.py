import subprocess

class BlockFromIPTables:
    def __init__(self):
        print("BlockFromIPTables loaded")
    
    def Run(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip}: {e}")
