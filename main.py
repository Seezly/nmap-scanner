import nmap

scanner = nmap.PortScanner()

print('Welcome')
print('===============')

ip_addr = input('Please enter the IP address you want to scan: ')
print('The IP you entered is: ' + ip_addr)

res = input(
    """
    \nPlease enter the type of scan you want to run:
    1. SYN ACK Scan
    2. UDP Scan
    3. Comprehensive Scan\n
    """
)
print("You have selected the option: " + res)

if res == '1':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ', scanner[ip_addr]['tcp'].keys())
elif res == '2':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ', scanner[ip_addr]['udp'].keys())
elif res == '3':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print("OS: ", scanner[ip_addr]['osmatch'][0]['osclass'][0]['osfamily'], scanner[ip_addr]['osmatch'][0]['osclass'][0]['vendor'])
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ', scanner[ip_addr]['tcp'].keys())
else:
    print('Please enter a valid option.')
    exit()