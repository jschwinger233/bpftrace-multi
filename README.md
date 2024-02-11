# bpftrace-multi

A [bpftrace](https://github.com/bpftrace/bpftrace) wrapper.

# Usage

Use bpftrace v0.19+.

```
Usage: sudo BPFTRACE_MAX_PROBES=4000 bpftrace-multi [filename]:

  -a, --all-kmods   Search all available kernel modules
  -n, --dry-run     Dry run
      --param-map   Generate @param map in BEGIN block
```

# Use cases

## 1. cilium/pwru

[Pwru](https://github.com/cilium/pwru) is working by attaching bpf to all kfuncs with `struct sk_buff *` parameter, let's do the same using bpftrace-multi.

Let's re-implement `pwru --output-meta --output-tuple 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn'`.

```
k:{{ has_param:sk_buff }}
{
    $skb = (struct sk_buff *){{ sk_buff }};
    $ip = (struct iphdr *)($skb->network_header+$skb->head);
    $tcp = (struct tcphdr *)($skb->transport_header+$skb->head);
    if ((uint8[4])($ip->daddr) == pton("1.1.1.1") && $tcp->syn == 1) {
        printf("%llx [%s(%lld)] ", $skb, comm, pid);
        printf("%s netns=%lld mark=%llx ", func, $skb->dev->nd_net.net->ns.inum, $skb->mark);
        printf("if=%d(%s) len=%lld ", $skb->dev->ifindex, $skb->dev->name, $skb->len);
        printf("%s:%d -> %s:%d\n", ntop($ip->saddr), bswap($tcp->source), ntop($ip->daddr), bswap($tcp->dest));
    }
}
```

Although a bit hassle (pwru can accept [pcap-filter](https://www.tcpdump.org/manpages/pcap-filter.7.html) while we have to parse packet headers on our own), we can achieve something pwru yet supports, such as:

### 1.1. [Output `skb->cb` and `skb->tc_index`](https://github.com/cilium/pwru/issues/295)

Just add another printf:

```
    printf("cb=%r tc_index=%ld ", buf($skb->cb, 48), $skb->tc_index);
```

### 1.2. [Attach kretprobe](https://github.com/cilium/pwru/issues/10)

Just add a `kr` block:

```
k:{{ has_param:sk_buff }}
{
    $skb = (struct sk_buff *){{ sk_buff }};
    $ip = (struct iphdr *)($skb->network_header+$skb->head);
    $tcp = (struct tcphdr *)($skb->transport_header+$skb->head);
    if ((uint8[4])($ip->daddr) == pton("1.1.1.1") && $tcp->syn == 1) {
        @traced[reg("sp")] = $skb;
        printf("> %llx %s()\n", $skb, func);
    }
}

kr:{{ has_param:sk_buff }}
{
    $skb = (struct sk_buff *)@traced[reg("sp")-8];
    if ($skb != 0) {
        printf("< %llx %s() = %lld\n", $skb, func, retval);
        delete(@traced[reg("sp")-8]);
    }
}

```

## 2. anakryiko/retsnoop

[Retsnoop](https://github.com/anakryiko/retsnoop) is watching retval on specific functions.

Instead of implementing a general retsnoop, let's troubleshoot something more specific: to find the function that fails `iptables -t mangle -I PREROUTING 1 -m mark --mark 0x200/0xf00 -j TPROXY --on-port 8080 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xf00` :

```
$ sudo iptables -t mangle -I PREROUTING 1 -m mark --mark 0x200/0xf00 -j TPROXY --on-port 8080 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xf00
iptables v1.8.9 (nf_tables):  RULE_INSERT failed (Invalid argument): rule in chain PREROUTING
```

First we must have some netfilter functions. Checkout kernel source, collect all the "export" symbols under `net/netfilter/`:

```
grep -Po '((?<=EXPORT_SYMBOL\()\w+)|((?<=EXPORT_SYMBOL_GPL\()\w+)' -r net/netfilter/  | awk -F: '{print $2}' | sort -u > netfilter.symbols
```

Then write a bpftrace-multi script:

```
k:{{ from_file:./netfilter.symbols }}
{
    if (comm == "iptables") {
        @traced[reg("sp")] = reg("ip")-1;
    }
}

kr:{{ from_file:./netfilter.symbols }}
{
    $ip = @traced[reg("sp")-8];
    if (retval != 0 && $ip != 0) {
        printf("non-zero retval: %s()=%lld %s\n", ksym($ip), retval, kstack);
    }
}
```

The output is like:

```
start tracing
non-zero retval: xt_find_revision()=1
        nfnl_compat_get_rcu+218
        nfnetlink_rcv_msg+501
        netlink_rcv_skb+90
        nfnetlink_rcv+108
        netlink_unicast+432
        netlink_sendmsg+606
        __sys_sendto+568
        __x64_sys_sendto+36
        do_syscall_64+88
        entry_SYSCALL_64_after_hwframe+110

non-zero retval: xt_find_revision()=1
        nfnl_compat_get_rcu+218
        nfnetlink_rcv_msg+501
        netlink_rcv_skb+90
        nfnetlink_rcv+108
        netlink_unicast+432
        netlink_sendmsg+606
        __sys_sendto+568
        __x64_sys_sendto+36
        do_syscall_64+88
        entry_SYSCALL_64_after_hwframe+110

non-zero retval: xt_request_find_target()=-1035308672
        nft_target_select_ops+173
        nf_tables_expr_parse+319
        nf_tables_newrule+812
        nfnetlink_rcv_batch+2076
        nfnetlink_rcv+318
        netlink_unicast+432
        netlink_sendmsg+606
        ____sys_sendmsg+1004
        ___sys_sendmsg+154
        __sys_sendmsg+137
        __x64_sys_sendmsg+29
        do_syscall_64+88
        entry_SYSCALL_64_after_hwframe+110

non-zero retval: xt_check_target()=4294967274
        nft_target_init+450
        nf_tables_newrule+1325
        nfnetlink_rcv_batch+2076
        nfnetlink_rcv+318
        netlink_unicast+432
        netlink_sendmsg+606
        ____sys_sendmsg+1004
        ___sys_sendmsg+154
        __sys_sendmsg+137
        __x64_sys_sendmsg+29
        do_syscall_64+88
        entry_SYSCALL_64_after_hwframe+110
```

## 3. Who changed my netdev?

This was the original reason why I created this tool. There was a misterious process changing my veth's mac address, and I wanted to find out that bad process.

The idea is to attach bpf to all kfuncs with parameter of type `struct net_device *`. By recording `dev->dev_addr` at kprobe, we can be aware of any change of `dev->dev_addr` at kretprobe.

```
k:{{ has_param:net_device }}
{
    $dev = (struct net_device *){{ net_device }};
    $dev_addr = (uint8*)($dev->dev_addr);
    @old[tid, reg("sp")] = ($dev, $dev_addr[0], $dev_addr[1], $dev_addr[2], $dev_addr[3], $dev_addr[4], $dev_addr[5]);
}

kr:{{ has_param:net_device }}
{
    $info = @old[tid, reg("sp")-8];
    if ($info.0 != 0) {
        $dev = (struct net_device *)$info.0;
        $new_addr = (uint8*)($dev->dev_addr);
        if ($new_addr[0] != $info.1 || $new_addr[1] != $info.2 || $new_addr[2] != $info.3 || $new_addr[3] != $info.4 || $new_addr[4] != $info.5 || $new_addr[5] != $info.6) {
            printf("%s's mac addr changed from %x:%x:%x", $dev->name, $info.1, $info.2, $info.3);
            printf(":%x:%x:%x ", $info.4, $info.5, $info.6);
            printf("to %s by %s(%lld)\n", macaddr($dev->dev_addr), comm, pid);
        }
    }
    delete(@old[tid, reg("sp")-8]);
}
```

The output is like:

```
start tracing
virbr0's mac addr changed from 52:54:0:62:1b:b1 to 52:54:00:62:1B:B2 by ip(59708)
virbr0's mac addr changed from 52:54:0:62:1b:b1 to 52:54:00:62:1B:B2 by ip(59708)
virbr0's mac addr changed from 52:54:0:62:1b:b1 to 52:54:00:62:1B:B2 by ip(59708)
virbr0's mac addr changed from 52:54:0:62:1b:b1 to 52:54:00:62:1B:B2 by ip(59708)
```
