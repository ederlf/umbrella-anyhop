# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu import cfg
from collections import namedtuple
import networkx as nx
import json
from struct import *

Port = namedtuple('Port', ['label', 'id', 'switch', 'mac', 'ip'])
Datapath = namedtuple('Datapath', ['name', 'dpid', 'area', 'participants', 'ports'])
Border = namedtuple('Border', ['src', 'src_port', 'dst', 'dst_port'])

class UmbrellaLINX(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(UmbrellaLINX, self).__init__(*args, **kwargs)

        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('topo_file', default='', help = ('The specification of the IXP')),
        ])

        self.areas = {} # Dictionary of Graphs
        self.datapaths= {}
        self.dpid_name= {}
        self.mac_to_port = {}
        self.paths = {}
        self.ports = []
        self.hops_area = {}
        self.borders = {}
        self._topo_from_json(CONF.topo_file);
        for a in self.areas:
            g = self.areas[a]
            self.paths[a] = {}
            paths = nx.all_pairs_shortest_path(g)
            for p in paths:
                self.paths[a][p[0]] = p[1]

    def _topo_from_json(self, conf):
        with open(conf) as json_data:
            d = json.load(json_data)
            areas = d["FabricSettings"]["dp_area"]
            for sw in areas:
                a = areas[sw]
                if a not in self.areas:
                    self.areas[a] = nx.Graph()
                self.areas[a].add_node(sw, area=a)
            

            dps = d["FabricSettings"]["dp_ids"]
            for dp in dps:
                self.datapaths[dp] = Datapath(dp, dps[dp], areas[dp], {}, [])
                self.dpid_name[dps[dp]] = dp

            links = d["FabricSettings"]["links"]
            for l in links:
                i = l.items()
                n1 = i[0][0]
                n2 = i[1][0]
                a1 = areas[n1]
                a2 = areas[n2]
                if a1 == a2:
                    self.areas[a1].add_edge(n1, n2, ports=l)
                else:
                    # Border key is composed by the src/dst areas
                    self.areas[a1].nodes[n1]["border"] = True
                    self.areas[a2].nodes[n2]["border"] = True
                    self.borders[(a1, a2)] = Border(n1, l[n1], n2, l[n2])
                    self.borders[(a2, a1)] = Border(n2, l[n2], n1, l[n1])
                self.datapaths[n1].ports.append(l[n1])
                self.datapaths[n2].ports.append(l[n2])

            hops_area = d["FabricSettings"]["hops_area"]
            for h in hops_area:
                self.hops_area[int(h)] = hops_area[h]

            members = d["Participants"]
            for m in members:
                ports = members[m]["Ports"]
                for p in ports:
                    dp = p['switch']
                    port = Port(m, p['Id'],dp , p['MAC'], p['IP'])
                    self.ports.append(port)
                    sw = self.datapaths[dp]
                    sw.participants[m] = port


    # Nhop is the maximum hop position a datapath can be in the path 
    def add_ingress_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        insw = self.datapaths[self.dpid_name[datapath.id]]
        for p in self.ports:
            # Destination is in the same switch, forward directly
            if p.switch == insw.name:
                match = parser.OFPMatch(eth_type=0x806, arp_op=1, arp_tpa=p.ip)
                actions = [parser.OFPActionOutput(p.id)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
                self.add_flow(datapath, 100, inst, match, 0)
                match = parser.OFPMatch(eth_dst=p.mac)            
                
            else:
                out_sw = self.datapaths[p.switch]
                inarea = insw.area
                outarea = out_sw.area
                # Switch and Destination are in the same area
                # Install flow that encodes the path to this switch
                if outarea == inarea:
                    path = self.paths[inarea][insw.name][out_sw.name]
                    mac = [0, 0]
                    # Do not consider first hop
                    out_port = self.areas[inarea][insw.name][path[1]]['ports'][insw.name]
                    for i in range(2, len(path)):
                        cur = path[i-1]
                        nxt = path[i]
                        ports = self.areas[inarea][cur][nxt]['ports']
                        # print ports
                        mac.append(ports[cur])
                    mac.append(p.id)
                    while len(mac) < 6:
                        mac.append(0)
                    mac_addr = ':'.join(map('{:02x}'.format, mac)).upper()
                    vid = datapath.ofproto_parser.OFPMatchField.make(
                            datapath.ofproto.OXM_OF_VLAN_VID, 0x1000 | 1)
                    actions = [parser.OFPActionSetField(eth_dst=mac_addr), parser.OFPActionPushVlan(),parser.OFPActionSetField(vid), parser.OFPActionOutput(out_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
                    match = parser.OFPMatch(eth_dst=p.mac)
                    self.add_flow(datapath, 1000, inst, match, 0)
                    match = parser.OFPMatch(eth_type=0x806, arp_op=1, arp_tpa=p.ip)
                    self.add_flow(datapath, 1000, inst, match, 0)
                else:
                    # Different areas, encode area, label and path to the 
                    # border switch
                    border_sw = self.borders[(inarea, outarea)].src
                    border_port = self.borders[(inarea, outarea)].src_port
                    path = self.paths[inarea][insw.name][border_sw]
                    # Packet came from another ingress switch in the same area
                    al = str(hex( (outarea << 12) | int(p.label) ))
                    head = [al[2:4], al[4:]]
                    tail = []
                    if len(path) > 1:
                        out_port = self.areas[inarea][insw.name][path[1]]['ports'][insw.name]
                        for i in range(2, len(path)):
                            cur = path[i-1]
                            nxt = path[i]
                            ports = self.areas[inarea][cur][nxt]['ports']
                            tail.append(ports[nxt])
                        tail.append(border_port)
                        while len(tail) < 4:
                            tail.append(0)
                        mac_addr = ':'.join(head) + ':' +':'.join(map('{:02x}'.format, tail)).upper()
                        vid = datapath.ofproto_parser.OFPMatchField.make(
                                datapath.ofproto.OXM_OF_VLAN_VID, 0x1000 | 1)
                        actions = [parser.OFPActionSetField(eth_dst=mac_addr), parser.OFPActionPushVlan(),parser.OFPActionSetField(vid), parser.OFPActionOutput(out_port)]
                    elif border_sw == insw.name:
                        # Ingress is a border switch
                        while len(tail) < 4:
                            tail.append(0)
                        mac_addr = ':'.join(head) + ':' +':'.join(map('{:02x}'.format, tail)).upper()
                        actions = [parser.OFPActionSetField(eth_dst=mac_addr), parser.OFPActionOutput(border_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
                    match = parser.OFPMatch(eth_dst=p.mac)
                    self.add_flow(datapath, 1000, inst, match, 0)
                    match = parser.OFPMatch(eth_type=0x806, arp_op=1, arp_tpa=p.ip)
                    self.add_flow(datapath, 1000, inst, match, 0)

    def add_hop_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        insw = self.datapaths[self.dpid_name[datapath.id]]
        nhop = self.hops_area[insw.area]
        for i in range(1, nhop+1):
            # Install flow to verify hop
            table = i + 1
            match = parser.OFPMatch(vlan_vid=i | 0x1000)
            inst = [parser.OFPInstructionGotoTable(table)]
            self.add_flow(datapath, 10000, inst, match, 0)
            mask = [0] * 6
            mask[table] = 0xff
            mask_mac = ':'.join(map('{:02x}'.format, mask)).upper()
            # Add flow to deliver to participants
            for p in insw.participants:
                port =  insw.participants[p] 
                mac = [0] * 6
                mac[table] = port.id
                mac_addr = ':'.join(map('{:02x}'.format, mac)).upper()
                match = parser.OFPMatch(eth_dst=(mac_addr, mask_mac), vlan_vid=0x1000 | i)
                actions = [parser.OFPActionSetField(eth_dst=port.mac), parser.OFPActionPopVlan(), parser.OFPActionOutput(port.id)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 1000, inst, match, table)
            
            for port in insw.ports:
                mac = [0] * 6
                mac[table] = port
                mac_addr = ':'.join(map('{:02x}'.format, mac)).upper()
                match = parser.OFPMatch(eth_dst=(mac_addr, mask_mac), vlan_vid=0x1000 | i)
                # Increase the HOP count
                actions = [parser.OFPActionSetField(vlan_vid= 0x1000 | (i+1)), parser.OFPActionOutput(port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 1000, inst, match, table)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_ingress_flows(datapath)
        self.add_hop_flows(datapath)
        # self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, inst,  match, table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                table_id=table, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
