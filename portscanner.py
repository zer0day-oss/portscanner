#!/usr/bin/env python3

import socket
import os
import threading
import sys
import subprocess
import argparse
from queue import Queue

parser = argparse.ArgumentParser(
    prog='portscanner',
    description='Python script that scans all 65535 ports quickly'
)

parser.add_argument('-i', '--ip', required=True, help='IP address to scan')
parser.add_argument('-n', '--nmap', action='store_true', help='Use nmap scan after discovering ports, outputting the results.')
args = parser.parse_args()
print(f"IP to scan: {args.ip}")


def main():
    socket.setdefaulttimeout(0.30)
    locked = threading.Lock()
    ports_found = []

    def scan_ports(port, retries=5):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            portx = s.connect((args.ip, port))
            for i in range(retries):
                with locked:
                    print("Port {} is open".format(port))
                    ports_found.append(str(port))
                portx.close()
        except (ConnectionRefusedError, AttributeError, OSError):
            pass 
        
    def threader():
        while True:
            worker = q.get()
            scan_ports(worker)
            q.task_done()
            
    q = Queue()
    
    for x in range(200):
        t = threading.Thread(target = threader)
        t.daemon = True 
        t.start()
        
    for worker in range(1, 65536):
        q.put(worker)
        
    q.join()
    
    print('Ports found:',','.join(ports_found))
        
    if args.nmap:
        print("Performing Nmap scan")
        nmap_ports = ','.join(ports_found)
        nmap_scan = subprocess.run(['nmap', '-A', '-vvv', 'p', nmap_ports, args.ip], capture_output=True, text=True)
        while True:
            nmap_output = input("Do you want to write to output? (Y/N): ")
            if nmap_output.upper() == "Y":
                with open("portscan.txt", "w", encoding="utf-8") as f:
                    print("Writing nmap scan result to output...")
                    f.write(nmap_scan.stdout)
                    break
                continue
            elif nmap_output.upper() == "N":
                print("Not writing to output.")
                break
            else:
                print("Do you want to write to output? (Y/N): ")
        print("Nmap output:\n", nmap_scan.stdout)  
               
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nQuitting program!")
        quit()