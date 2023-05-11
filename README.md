# README

## Prerequisites

For Fedora (and probably RHEL/CentOS)
```bash
sudo dnf install iptables-devel libnfnetlink-devel libnetfilter_acct libnetfilter_queue-devel
```

This will give you all the necessary libraries to compile the code. 

## Usage
To use this we make the rule for the iptables and then we run the code. Finally to stop the program we flush the iptables rules and then stop the program.

```bash
$ sudo iptables -I FORWARD -j NFQUEUE
```

This rule sends every packet that had to be forwarded by the router to the NFQUEUE. The router then makes the decision to drop or accept the packet.

To compile the code and run the program:
```bash
$ g++ -o packet_monitor main.cpp -libnetfilter_queue
$ sudo ./packet_monitor
```
NOTE: Without sudo the program will face binding issues. 

```bash
$ sudo iptables -F
```

This command flushes all the iptables rules.

## Working

The code has 3 threads:

- This main thread which is responsible for taking the input from the user and then making the descision to drop or accept the packet.
- This thread clears the map that is used to maintain the bandwidth usage of each IP address.
- This thread clears the map that is used to maintain the total data usage of each IP address.

