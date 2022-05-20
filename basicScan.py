import sys
import socket as s
import datetime

# options for port numbers to check (basic is the default)
def basic(ipAddress):
    list = [21, 22, 25, 80, 110, 143, 443, 445, 502, 587, 993, 995, 2525, 3306, 3389]
    scanIPs(ipAddress, list)


def web(ipAddress):
    list = [23, 43, 53, 67, 68, 69, 123, 161, 162, 213, 389, 636, 989, 990,
            1720, 2082, 2083, 2086, 2087, 2095, 2096]
    scanIPs(ipAddress, list)


def malicious(ipAddress):
    list = [26, 1080, 2745, 3127, 4444, 5554, 8866, 9898, 12345, 27374, 31337]
    scanIPs(ipAddress, list)


# going through the list of ports
def scanIPs(ipAddress, list):
    # 65,535 is the max port number
    for portNum in list:
        # starting a new connection
        socket = s.socket(s.AF_INET, s.SOCK_STREAM)

        IPnPort = (ipAddress, portNum)
        checkConnection = socket.connect_ex(IPnPort)
        if checkConnection == 0:
            # port connection is open
            print("Port ", portNum, " connection is open")
        socket.close()

    print("Scan Completed")
    exit(0)


# take in an IP address and scan for open ports (specified by port type)
argNum = len(sys.argv)
if argNum < 2 or argNum > 3:
    print("Usage: portScanner.py [IP Address] [Scan Type: basic, web, malicious]")
    exit(1)
else:
    ipAddress = s.gethostbyname(sys.argv[1])

    # if no scan type given, do a basic scan
    print("Target IP Address: ", ipAddress)
    print("Starting port scan at [", datetime.datetime.now(), "]")
    if argNum == 2:
        basic(ipAddress)

    scanType = sys.argv[2]

    if scanType in ["basic", "web", "malicious"]:
        print("Target IP Address: ", ipAddress)
        print("Scan Type: ", scanType)
        print("Starting port scan at [", datetime.datetime.now(), "]")

        if scanType == "basic":
            basic(ipAddress)
        elif scanType == "web":
            web(ipAddress)
        else:
            malicious(ipAddress)
    else:
        print("Desired Scan Type Not Listed")
        exit(1)

