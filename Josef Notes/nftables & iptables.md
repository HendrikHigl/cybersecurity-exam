iptables Listen anzeigen
`sudo iptables -L`

Flush iptables Ruleset
`sudo iptables -F`

Flush nftables Ruleset
`sudo nft flush ruleset`

https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

Beispiel nftables Ruleset
```
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established, related accept
                ip saddr 10.166.0.226 accept;
                icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept 
        }
        chain forward {
                type filter hook forward priority filter; policy drop;
                ct state established, related accept
                ip daddr 10.166.163.10 tcp dport 81 drop
                ip daddr 10.166.163.10 accept

                ip6 daddr fd50:52:166:163::10 icmpv6 type echo-request drop
                ip6 daddr fd50:52:166:163::10 accept
        }
        chain output {
                type filter hook output priority filter;
        }
}
```

Musterlösung Firewall Challenge
```
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    # default policy is drop to use a secure default
    type filter hook input priority filter; policy drop;
    # allow known connections
    ct state vmap { invalid : drop, established : accept, related : accept }

    icmp type echo-request limit rate 15/second counter accept
    icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert, mld-listener-query } accept
    icmpv6 type echo-request limit rate 15/second counter accept

    # disallow servers in the server network to connect to SSH
    ip saddr 10.129.162.0/24 tcp dport 22 counter reject
    ip6 saddr fd50:52:129:162::/64 tcp dport 22 counter reject
    # allow port 22 (ssh) for everyone else
    tcp dport 22 counter accept
  }
  chain forward {
    # default policy is drop to use a secure default
    type filter hook forward priority filter; policy drop;
    ct state vmap { invalid : drop, established : accept, related : accept }

    # allow connections to port 80 and 81 (ipv6 only) from server network (162) to target network
    iifname eth0 oifname eth1 tcp dport 80 accept
    iifname eth0 oifname eth1 meta nfproto ipv6 tcp dport 81 accept

    # allow echo requests for IPv4 to target network
    iifname eth0 oifname eth1 meta nfproto ipv4 icmp type 8 accept
  }
  chain output {
    type filter hook output priority filter;
  }
}

#table inet nat {
#  chain prerouting {
#    type nat hook prerouting priority dstnat; policy accept;
#    ip6 daddr fd50:52:129:163::10 tcp dport {80, 443} counter dnat to [fd50:52:129:162::2]:8080;
#  }
#}
```