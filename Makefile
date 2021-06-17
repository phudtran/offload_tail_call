all:
	clang-7 -I. -Wno-compare-distinct-pointer-types -O3 -DDEBUG -D__KERNEL__ -g -D__BPF_TRACING__  -target bpf -c eth.c -o eth.o
	clang-7 -I. -Wno-compare-distinct-pointer-types -O3 -DDEBUG -D__KERNEL__ -g -D__BPF_TRACING__  -target bpf -c veth.c -o veth.o

veth_pair:
	ip netns add net0 && \
	ip link add inside type veth peer name outside && \
	ip link set inside netns net0 && \
	ip netns exec net0 ip addr add 10.0.0.4/24 dev inside && \
	ip netns exec net0 ip link set dev inside up && \
	ip netns exec net0 sysctl -w net.ipv4.tcp_mtu_probing=2 && \
	ip netns exec net0 ethtool -K inside tso off gso off ufo off && \
	ip netns exec net0 ethtool --offload inside rx off tx off && \
	ip link set dev outside up mtu 9000 && \
	ip netns exec net0 route add default gw 10.0.0.1 &&  \
	ip netns exec net0 ifconfig lo up &&  \
	ip netns exec net0 ifconfig inside hw ether 00:00:00:00:00:0a

load_eth:
	ip link set dev eth0 xdpoffload off
	ip link set dev eth0 xdpoffload obj eth.o sec xdp

load_veth:
	ip link set dev outside xdpgeneric off && \
	ip link set dev outside xdpgeneric obj veth.o sec xdp

netronome_setup:
	rmmod nfp; modprobe nfp && \
	ip link set enp1s0np0 name eth0 && \
	ip a add 10.0.0.3/24 dev eth0 && \
	ip link set eth0 up

clean:
	rm -f *.o
clean_up:
	ip l delete outside
	ip netns delete net0

# ./bpftool map update id jmp_table_id key 01 00 00 00 value id XDP_PROGRAM_ID (via IP LINK)