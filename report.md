---
title: Data and Bandwidth Limiter + Firewall 
author: Suryaansh Jain, Kartheek Tamanna, Rutv Kocheta
---

### Abstract

We are going to have multiple VMs running on the same host (all in the same network). One of the VMs will be the firewall (router), and the other VMs will be the clients. The firewall will be running a program that will monitor the amount of data used by each client. If the data limit is reached, the firewall will block all traffic from that client. The firewall will also monitor the bandwidth used by each client. If the bandwidth limit is reached, the firewall will throttle that client. The firewall will also block certain types of traffic (eg: DNS, HTTP, etc.) and certain websites/IP addresses (eg: ad sites).

### Features

- Set a cap on the amount of data that can be used (eg: 1GB/day per device).
- Set a maximum bandwidth limit (eg: 30mbps per user).
- Allow/block traffic from certain ports (eg: 80, 443, 22, etc).
- Allow/block certain types of traffic (eg: DNS, HTTP, etc).
- Block certain websites/IP addresses (eg: ad sites).
- maintain traffic logs

### Future Extensions

- add a login system so that the limit will be per user and not per device
- run on physical devices instead of VMs (can use WiFi login system)
- add a user-friendly interface for admins
- Use logs to generate reports and plots