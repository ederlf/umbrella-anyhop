## Extension of the Umbrella encoding for IXPs with multiple hops

This application implements a label encoding scheme to forward packets in a large Internet Exchange Point (IXP).

The solution encodes the the path of a packet as a series of ports in the MAC address. The first two bytes are reserved to encode the area and a label identifier from the participants of the IXP. In these two bytes, the initial 4 bits contain the area while the remaining 12 are for the label. Each of the last 4 bytes encode the next port of the path.

Example: a packet with the encoding **10:03:01:02:00:00**
```
Area is 01
Label is 3
The exit port in the first path is 01.
The exit port in the second hop  is 02.
```
To know which hop is the current switch a packet traverses, the VLAN id
is leveraged to store the hop count. When a packet enters the IXP, the path to the destination is calculated and encoded in the destination MAC and a VLAN tag with value equal to 1 is added to the packet. For every next hop, until the packets reaches the final destination, the next port is decided by a flow that matches only the bytes of the destination MAC in the position of the VLAN id. 

Example: for the packet **10:03:01:02:00:00** in different hops,
the match fields are as following

```
First Hop
vlan_vid = 1, eth_dst=00:00:01:00:00:00/00:00:ff:00:00:00

Second Hop:
vlan_vid = 2, eth_dst=00:00:00:02:00:00/00:00:00:ff:00:00
```

The switch tables are defined as:

**HOP_AREA_TABLE**: This table matches in the area or a vlan that identifies the hop. 

**LABEL_TABLE**: This table is only present at border switches. It matches in the label and rewrite the original MAC address. 

**INGRESS_TABLE**: When a packet enters the IXP fabric or a new area, this table matches on the MAC address or IP destination of an ARP request and encodes the area, label and path in the destination MAC. It also has flows to forward directly to participants connected the same switch.

**NEXT_HOP_TABLES**: These match based on the hop count in the VLAN id and the position in the encoded path to forward packets. The number of tables is equal to the number of possible positions in a path for the switch.

