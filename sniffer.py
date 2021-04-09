import threading, socket, sys, math


def is_port_open(host, port, delay, output):
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mysocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    location = (host, port)
    mysocket.settimeout(delay)
    result_of_check = mysocket.connect_ex(location)
    if result_of_check == 0:
        output[port] = True
    else:
        output[port] = False


def threadingPortSniffs(host, delay, thread_num, sniff_cfg, port_range):
    threads = []
    output = {}
    start = port_range[0]
    end = port_range[1]
    tr_len = math.floor((end - start) / thread_num)
    p = start
    if tr_len == 0:
        tr_len = 1
        thread_num = end - start
    for i in range(thread_num - 1):
        t = threading.Thread(target=checkPorts, args=(host, delay, (p, p + tr_len), output))
        p = p + tr_len
        threads.append(t)
    t = threading.Thread(target=checkPorts,
                         args=(host, delay, (p, end), output))

    threads.append(t)

    for i in range(thread_num):
        threads[i].start()
    for i in range(thread_num):
        threads[i].join()
    print("[>] Host: <" + host + ">:")
    for i in range(len(output)):
        if output[i]:
            print("    [+] Port <" + str(i) + "> -> Listening ")
        else:
            print("    [-] Port <" + str(i) + "> -> NoN ")


def checkPorts(host, delay, port_range, output):
    for i in range(port_range[0], port_range[1] + 1):
        is_port_open(host, i, delay, output)


def parser():
    for i in range(len(sys.argv)):
        # sniff_cfg = []
        if sys.argv[i] == "-h":
            host = sys.argv[i + 1]
            i = i + 1
        elif sys.argv[i] == "-t":
            thread_num = int(sys.argv[i + 1])
            i = i + 1
        elif sys.argv[i] == "-d":
            delay_time = int(sys.argv[i + 1])
            i = i + 1
        elif sys.argv[i] == "-all":
            sniff_cfg = "all"
        elif sys.argv[i] == "-res":
            sniff_cfg = "res"
        elif sys.argv[i] == "-serv":
            sniff_cfg = "serv"
        elif sys.argv[i][0] == "[" and sys.argv[i][-1] == "]":
            start = int(sys.argv[i][1: sys.argv[i].index(':')])
            end = int(sys.argv[i][sys.argv[i].index(':') + 1:-1])
            port_range = (start, end)

    return host, thread_num, delay_time, sniff_cfg, port_range

# "-h google.com -t 100 -d 20 -all [1:350]"
