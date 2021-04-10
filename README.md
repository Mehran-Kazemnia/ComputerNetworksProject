# ComputerNetworksProject
At the first phase of project we should do:
- [x] Implementing port sniffing for ports of host (in a particular range)
- [x] Implementing multi thread port sniffing
- [x] Get `delay_time`, `number of threads` and `host` from input `args`
- [x] Implementing three services:
    - Sniff a particular port range
    - Sniff wellknown ports 
    - Sniff Services ports 

### Guide
You can use this flags to set the configuration of the sniffing( * are necessary):
- * `-h`: determining host ip
- * `-t`: determining maximum number of threads
- * `-d`: setting the waiting time for each port sniff
- * `[start:end]`: to config ports range
Choose one of these( `all` is default):
- `-all`: Sniff a particular port range
- `-wlp`: Sniff wellknown ports
- `-serv`: Sniff Services ports
#### Example

```
>>> py main.py -h google.com -t 1000 -d 5 [0:350]

```

```
>>> py main.py -h google.com -t 1000 -d 5 -wlp [50:350]

```
### [Repository Address](https://github.com/Mehran-Kazemnia/ComputerNetworksProject)
