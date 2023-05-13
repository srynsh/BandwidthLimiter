---
title: Data and Bandwidth Limiter + Firewall 
author: Suryaansh Jain, Kartheek Tamanna, Rutv Kocheta
---

### Abstract

The firewall is a program that monitors the amount of data used by each client. If the data limit is reached, the firewall will block all traffic from that client. The firewall will also monitor the bandwidth used by each client. If the bandwidth limit is reached, the firewall will throttle that client. The firewall also blocks certain types of traffic (eg: DNS, HTTP, etc.) and certain websites/IP addresses (eg: ad sites).

### Features

- run on physical devices instead of VMs (can use WiFi login system)
- Set a cap on the amount of data that can be used (eg: 1GB/day per device).
- Set a maximum bandwidth limit (eg: 30Mbps per user).
- Allow/block traffic from certain ports (eg: 80, 443, 22, etc).
- Allow/block certain types of traffic (eg: DNS, HTTP, etc).
- Block certain IP addresses (eg: 1.1.1.1).
- maintain traffic logs

### Future Extensions

- add a login system so that the limit will be per user and not per device
- add a user-friendly interface for admins
- Use logs to generate reports and plots

### Design Details

- We have in total 3 threads:
  - The first thread gets packets from the NFQUEUE and decides their fate.
  - The second thread resets the map that stores the speed every time interval.
  - The third resets the map that stores the total data used in the day.
- 