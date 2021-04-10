from sniffer import *


def main():
    host, thread_num, delay_time, sniff_cfg, port_range = parser()
    print(('- ') * 20)
    print(" | host: <" + host + ">")
    print(" | max threads: <" + str(thread_num) + ">")
    print(" | delay time: <" + str(delay_time) + ">")
    print(" | cfg: <" + sniff_cfg + ">")
    print(" | port range: (" + str(port_range[0]) + "," + str(port_range[1]) + ")")
    print(('- ') * 20)
    threadingPortSniffs(host, delay_time, thread_num, sniff_cfg, port_range)
    print("Finished successfully!")
    print(('- ') * 20)

if __name__ == "__main__":
    main()
