# ComputerNetworksProject
At the first phase of project we should do:
- [x] implementing port sniffing for ports of host (in a particular range)
- [x] implementing multi thread port sniffing
- [x] get `delay_time`, `number of threads` and `host` from input `args`

### Guide
You can use this flags to set the configuration of the sniffing:
- `-h`: determining host ip
- `-t`: determining maximum number of threads
- `-d`: setting the waiting time for each port sniff
- `[start:end]`: to config ports range
#### Example

```
>>> py main.py -h google.com -t 1000 -d 5 [0:350]

```
