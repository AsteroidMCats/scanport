#!/usr/bin/python3

import sys, re

protor = r'tcp|tcp6'
addr = r'((\S)+):(\d+|\*)'
stater = r'[A-Z]+'
#pidr = r'[A-Z]+ +(-|.+)'

extServs = set({})
internServs =set({})
uProgsLis = 0
ongConnects = 0
upPersonal = 0
ongConnectsPersonal = 0

unprocessedLines = 0


for line in sys.stdin:
    if re.search(protor, line[:4]):
        address = re.search(addr, line)
        ip = address[1]
        port = address[3]

        state = re.search(line, stater)
        pid = (line.split())[5]

        #re.search(line, pidr)
        
        #print(f'Processed Line: \n ip = {ip} \n port = {port}')

        if (ip == '127.0.0.1') | (ip == '::1'):
            internServs.add(port)
            if state == "LISTEN":
                uProgsLis += 1
                if pid != "-":
                    upPersonal += 1
        else:
            extServs.add(port)

        if state != "LISTEN":
            ongConnects += 1
            if pid != "-":
                ongConnectsPersonal += 1
        
    else:
        unprocessedLines += 1

print(f'Unprocessed Lines: {unprocessedLines}\n')
print(f'{len(extServs)} external services\n{len(internServs)} internal services\n{uProgsLis} user programs listening ({upPersonal} mine)\n{ongConnects} ongoing connections ({ongConnectsPersonal} mine)')
