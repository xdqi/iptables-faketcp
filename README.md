# faketcp

A netfilter extension and an iptables extension to transmission UDP with fake TCP headers.

Inspired by udp2raw. 

## Install

```
cd ko
make install
cd so
make install
```

## Usage

```
iptables -t mangle -A OUTPUT -p udp -m udp -d 10.0.0.1 --dport 8080 -j FAKETCP --mode 0
iptables -t mangle -A INPUT -p tcp -m tcp -s 10.0.0.1 --sport 8080 -j FAKETCP --mode 0
```

FakeTCP client connect to 10.0.0.1:8080

```
iptables -t mangle -A INPUT -p tcp -m tcp -d 10.0.0.1 --dport 8080 -j FAKETCP --mode 0
iptables -t mangle -A OUTPUT -p udp -m udp -s 10.0.0.1 --sport 8080 -j FAKETCP --mode 0
```
FakeTCP server listening on 10.0.0.1:8080

## Modes

FakeTCP includes several modes to encapsulate UDP packet like TCP

0. plain
> Just exchange IPPROTO_TCP(6) with IPPROTO_UDP(17) in IP headers
