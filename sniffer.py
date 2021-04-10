import threading, socket, sys, math

wellknown_ports = [1,
                   5,
                   7,
                   18,
                   20,
                   21,
                   22,
                   23,
                   25,
                   29,
                   37,
                   42,
                   43,
                   49,
                   53,
                   69,
                   70,
                   79,
                   80,
                   103,
                   108,
                   109,
                   110,
                   115,
                   118,
                   119,
                   137,
                   139,
                   143,
                   150,
                   156,
                   161,
                   179,
                   190,
                   194,
                   197,
                   389,
                   396,
                   443,
                   444,
                   445,
                   458,
                   546,
                   547,
                   563,
                   569,
                   1080]


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
    if sniff_cfg == "serv":

        thread_num = 1
        ch = int(input("Choose Service:\n1-HTTP\n2-TLS\n3-SMTP\n4-FTP\n5-TELNET\n6-SSH\n"))

        if ch == 1:
            service_port = 80
            print("@HTTP ->")
        elif ch == 2:
            service_port = 143
            print("@TLS ->")
        elif ch == 3:
            service_port = 25
            print("@SMTP ->")
        elif ch == 4:
            service_port = 21
            print("@FTP ->")
        elif ch == 5:
            service_port = 23
            print("@TELNET ->")
        elif ch == 6:
            service_port = 22
            print("@SSH ->")

        t = threading.Thread(target=is_port_open, args=(host, service_port, delay, output))
        threads.append(t)


    elif sniff_cfg == "wlp":
        tr_len = math.floor(len(wellknown_ports) / thread_num)
        p = 0
        if tr_len == 0:
            tr_len = 1
            thread_num = len(wellknown_ports)

        for i in range(thread_num - 1):
            t = threading.Thread(target=checkwellknownPorts, args=(host, delay, (p, p + tr_len), output))
            p = p + tr_len
            threads.append(t)
        t = threading.Thread(target=checkwellknownPorts,
                             args=(host, delay, (p, len(wellknown_ports) - 1), output))
        threads.append(t)
    else:
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
    for key in output:
        if output[key]:
            print("    [+] Port <" + str(key) + "> -> Listening ")
        else:
            print("    [-] Port <" + str(key) + "> -> NoN ")


def checkPorts(host, delay, port_range, output):
    for i in range(port_range[0], port_range[1] + 1):
        is_port_open(host, i, delay, output)


def checkwellknownPorts(host, delay, port_range, output):
    for i in range(port_range[0], port_range[1] + 1):
        is_port_open(host, wellknown_ports[i], delay, output)


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
        elif sys.argv[i] == "-wlp":
            sniff_cfg = "wlp"
        elif sys.argv[i] == "-serv":
            sniff_cfg = "serv"
        elif sys.argv[i][0] == "[" and sys.argv[i][-1] == "]":
            start = int(sys.argv[i][1: sys.argv[i].index(':')])
            end = int(sys.argv[i][sys.argv[i].index(':') + 1:-1])
            port_range = (start, end)

    return host, thread_num, delay_time, sniff_cfg, port_range

