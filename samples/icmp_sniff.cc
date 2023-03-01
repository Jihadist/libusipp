// c++ icmp_sniff.cc -lusi++ -lpcap -ldnet
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <usi++/usi++.h>
#include <cstdlib>
#include <cstring>
#include <future>
#include <iostream>
#include <string>
#include <thread>
using namespace std;
using namespace usipp;

int main(int argc, char** argv) {
  // must be a pcap RX, init_device() already called

  struct ifaddrs* ifaddr;
  int family, s;
  char host[NI_MAXHOST];

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  /* Walk through linked list, maintaining head pointer so we
            can free list later. */

  for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    family = ifa->ifa_addr->sa_family;

    /* Display interface name and family (including symbolic
              form of the latter for the common families). */

    printf("%-8s %s (%d)\n", ifa->ifa_name,
           (family == AF_PACKET)  ? "AF_PACKET"
           : (family == AF_INET)  ? "AF_INET"
           : (family == AF_INET6) ? "AF_INET6"
                                  : "???",
           family);

    /* For an AF_INET* interface address, display the address. */

    if (family == AF_INET || family == AF_INET6) {
      s = getnameinfo(ifa->ifa_addr,
                      (family == AF_INET) ? sizeof(struct sockaddr_in)
                                          : sizeof(struct sockaddr_in6),
                      host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      if (s != 0) {
        printf("getnameinfo() failed: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
      }

      printf("\t\taddress: <%s>\n", host);

    } else if (family == AF_PACKET && ifa->ifa_data != NULL) {
      struct rtnl_link_stats* stats =
          static_cast<rtnl_link_stats*>(ifa->ifa_data);

      printf(
          "\t\ttx_packets = %10u; rx_packets = %10u\n"
          "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
          stats->tx_packets, stats->rx_packets, stats->tx_bytes,
          stats->rx_bytes);
    }
  }

  freeifaddrs(ifaddr);

  std::packaged_task<int()> task([] {
    while (1) {
      ICMP icmp("77.88.55.70");
      icmp.set_src("192.168.88.251");
      icmp.set_type(numbers::icmp_echo);
      icmp.sendpack(std::string(256, 'a'));
      sleep(1);
    }
    return 1;
  });                                       // wrap the function
  std::future<int> f1 = task.get_future();  // get a future
  std::thread t(std::move(task));           // launch on a thread

  std::packaged_task<int()> task2([] {
    ICMP icmp("127.0.0.1");
    string src = "", dst = "", l2 = "", pkt = "";

    char buf[usipp::min_packet_size] = {0};

    if (icmp.init_device("wlo1", 1, 1500) < 0) {
      cerr << icmp.why() << endl;
      return 1;
    }

    auto rx = icmp.rx();
    cout << "refcount of RX: " << rx.use_count() << endl;
    while (1) {
      // blocks
      int r = icmp.sniffpack(buf, sizeof(buf));
      cerr << r << endl;
      if (r < 0) {
        cerr << icmp.why() << endl;
        continue;
      }
      cout << "[" << bin2mac(icmp.rx()->get_l2src(l2)) << "->"
           << bin2mac(icmp.rx()->get_l2dst(l2)) << "]:";
      cout << "type:" << (int)icmp.get_type() << " [" << icmp.get_src(src)
           << " -> " << icmp.get_dst(dst) << "] "
           << "seq: " << icmp.get_seq() << " ttl: " << (int)icmp.get_ttl()
           << " id: " << icmp.get_icmpId() << endl;
      //<<buf<<endl;
    }
  });                                        // wrap the function
  std::future<int> f2 = task2.get_future();  // get a future
  std::thread t2(std::move(task2));          // launch on a thread

  f1.wait();
  f2.wait();

  t.join();
  t2.join();

  return 0;
}
