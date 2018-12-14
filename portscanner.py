import argparse
import socket
from datetime import datetime

def connScan(tgtHost, tgtPort):
    try:
        print(datetime.now())
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = connSkt.connect_ex((tgtHost, tgtPort))

        if result == 0:
            print("[+] {} /tcp open".format(tgtPort))
        else:
            print("[-] {} /tcp closed".format(tgtPort))


        connSkt.close()
    
    except:
        print("Error. . .!")


def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = socket.gethostbyname(tgtHost)

    except:
        print("[-] Cannot resolve {}: Unknown host".format(tgtHost))
        return
    
    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        print("[+] Scan results for: {}".format(tgtName[0]))

    except:
        print("[+] Scan results for: {}".format(tgtIP))

    socket.setdefaulttimeout(1)
    
    for tgtPort in tgtPorts:
        print("Scanning port {}".format(tgtPort))
        connScan(tgtHost, int(tgtPort))


def main():
    parser = argparse.ArgumentParser(description="Port Scanner")

    parser.add_argument("-H", "--tgtHost", help="specify target host")
    parser.add_argument("-p", "--tgtPort", help="specify target port[s] separated by comma")

    args = parser.parse_args()

    tgtHost = args.tgtHost
    tgtPort = args.tgtPort

    if(args.tgtPort == None and args.tgtHost == None):
        print(parser.print_help())
        exit(0)

    if(args.tgtPort == None):
        print("ERROR. Please specify target port[s]")
        exit(0)

    if(args.tgtHost == None):
        print("ERROR. Please specify target host")
        exit(0)

    try:
        tgtPorts = tgtPort.split(",")
        portScan(tgtHost, tgtPorts)
    except:
        print("ERROR. Enter comma separated port numbers")

if __name__ == "__main__":
    main()