# port-scanners

basicScan.py Usage: python3 portScanner.py [IP Address] [Scan Type: basic, web, malicious]

Use python3 portScanner.py $(python3 getIP.py) [Scan Type: basic, web, malicious] to obtain your local IP address and conduct a scan on it.

The basic (default) scan analyzes common ports like TCP 22, 80, 110, 143, etc.
The web scan looks at ports relating to website activity like DNS requesting.
The malicious scan looks at ports that are linked with malicious programs or behavior. This includes port 2745 for the Bagle virus and others.
