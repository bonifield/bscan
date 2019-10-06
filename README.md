# bScan
### Simple Python Network and DNS Query Scanner

### requires [IPv4Helper](https://github.com/bonifield/IPv4Helper) library for CIDR generators

# Scan Modes
```syn, xmas, fin, null, ack, udp, dns```

# Output Modes
```color (default), pipe, tsv, csv, json, none```

# Usage Examples:
```
bscan.py -i 192.168.1.10 -p 80,443 -m syn -t 2
bscan.py -i 192.168.1.10/28 -p 80,443 -m syn -y csv
bscan.py --ip 192.168.1.10 --port 80,443 --mode syn --timeout 2 --data 50
bscan.py -i 192.168.1.10/28 -p 80,100-200,443 -m syn -d 50 --outputstyle pipe
bscan.py -i 192.168.1.10 -p 53 -m udp -y json
bscan.py -i 192.168.1.10 -p 53,5353 -m dns -q stackoverflow.com
```
