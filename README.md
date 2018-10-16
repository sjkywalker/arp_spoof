# ARP Spoof

Poisons the sender *and* the target's arp table and sniffs network packets (ethertype ip) that flow between the two entities.

## Getting started

### Overview

* Attacker sniffs the packets between sender and target
* There's no real difference between the `sender` and `target` because a single pair of hosts <sender, target> will
    * infect both of them
    * relay packets from sender to target, and vice versa
* sender and target's roles are *symmetric*
    * thus `sender == host1`, and `target == host2`
* Therefore multiple sessions support is unnecessary
* Multiple arp spoofing sessions can be created by executing the program in another shell with a different pair of hosts as argument

### Program flow

1. Poison sender's ARP table
2. Poison target's ARP table
3. Create thread that periodically poisons ARP tables of both sender and target (SEND_ARP(void *))
    * default period set to 5 seconds, but user can easily alter the value
    * `SEND_ARP_PERIOD` defined in `functions.h`
4. Create thread that prevents ARP table recovery in both sender and target (BLOCK_RECOVERY(void *))
5. Main thread relays the following IP packets
    * sender -> attacker -> target: (pkt.smac == sender.mac) && (pkt.dmac == attacker.mac) && (pkt.dip != attacker.ip)
    * target -> attacker -> sender: (pkt.smac == target.mac) && (pkt.dmac == attacker.mac) && (pkt.dip != attacker.ip)
    * **should not filter with source ip, since packets incoming from outside the network will have different source ip address from sender and target**

### Interface

There are four classes in how network packet flows are displayed.

* [  INIT  ]
    * The first fake ARP packet sent to sender and target
    * [- INIT -] when error, followed by error message
* [  PROD  ]
    * Fake ARP replies sent periodically
    * [- PROD -] when error, followed by error message
* [  RINF  ]
    * Reinfection ARP packets
    * Reinfection occurs when ARP request broadcast is sensed
    * [- RINF -] when error, followed by error message
* [  RLAY  ]
    * Relayed ETHERTYPE IP packets
    * [- RLAY -] when error, followed by error message

### Development Environment

```txt
$ uname -a
Linux ubuntu 4.15.0-36-generic #39~16.04.1-Ubuntu SMP Tue Sep 25 08:59:23 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

$ g++ --version
g++ (Ubuntu 5.4.0-6ubuntu1~16.04.10) 5.4.0 20160609
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

### Prerequisites

This program includes the following headers. Make sure you have the right packages.

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <libnet.h>
#include <time.h>
#include <pthread.h>
```

The following commands will install some of the essential packages.

```bash
$ sudo apt-get install libpcap-dev
$ sudo apt-get install libnet-dev
```

*Turn off the `Jumbo Frame` option in your network settings to avoid `send: Message too long` error in the `pcap_sendpacket` function.*

## Running the program

### Build

Simply hit `make` to create object files and executable binary.

```bash
$ make
```

### Run

Format

```bash
$ ./arp_spoof <interface> <sender ip> <target ip>
```

Example

```bash
$ ./arp_spoof eth0 172.16.28.150 172.16.28.1
```

You might need root priviledges to capture, send, and monitor network packets.

## Acknowledgements

* [Get my IP address](https://www.sanfoundry.com/c-program-get-ip-address/)
* [Get my MAC address](https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program)
* [Send ARP](https://github.com/sjkywalker/send_arp)
* [ARP Spoofing](https://gitlab.com/gilgil/network/wikis/arp-spoofing/arp-spoofing)

## Authors

* **James Sung** - *Initial work* - [sjkywalker](https://github.com/sjkywalker)
* Copyright © 2018 James Sung. All rights reserved.
