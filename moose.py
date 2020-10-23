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
import itertools

"""
This application implements MOOSE forward packets in an Internet Exchange Point (IXP). 
https://www.cl.cam.ac.uk/~mas90/MOOSE/MOOSE.pdf
"""


Port = namedtuple('Port', ['label', 'id', 'switch', 'mac', 'ip',
                  'moose_address'])
Datapath = namedtuple('Datapath', ['name', 'dpid', 'area', 'participants', 'ports', 'label'])
Border = namedtuple('Border', ['src', 'src_port', 'dst', 'dst_port'])


class MOOSE(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    INGRESS_TABLE = 0
    EDGE_TABLE = 1

    def __init__(self, *args, **kwargs):
        super(MOOSE, self).__init__(*args, **kwargs)

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
        self.full_graph = nx.Graph()
        self._topo_from_json(CONF.topo_file);
        self.all_paths = dict(nx.all_pairs_shortest_path(self.full_graph))
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
                self.full_graph.add_node(sw)

            dps = d["FabricSettings"]["dp_ids"]
            for dp in dps:
                label = "00:00:%02x" % dps[dp]
                self.datapaths[dp] = Datapath(dp, dps[dp], areas[dp], {}, [], label)
                self.dpid_name[dps[dp]] = dp

            print dps
            links = d["FabricSettings"]["links"]
            for l in links:
                i = l.items()
                n1 = i[0][0]
                n2 = i[1][0]
                a1 = areas[n1]
                a2 = areas[n2]
                self.full_graph.add_edge(n1, n2, ports=l)
                self.full_graph.add_edge(n2, n1, ports=l)
                border = False
                if a1 == a2:
                    self.areas[a1].add_edge(n1, n2, ports=l)
                    self.areas[a2].add_edge(n2, n1, ports=l)
                    self.areas[a1].nodes[n1]["border"] = False
                    self.areas[a2].nodes[n2]["border"] = False
                else:
                    # Border key is composed by the src/dst areas
                    self.areas[a1].nodes[n1]["border"] = True
                    self.areas[a2].nodes[n2]["border"] = True
                    self.borders[(a1, a2)] = Border(n1, l[n1], n2, l[n2])
                    self.borders[(a2, a1)] = Border(n2, l[n2], n1, l[n1])
                    border = True
                self.datapaths[n1].ports.append(( l[n1], border, n2) )
                self.datapaths[n2].ports.append(( l[n2], border, n1) )

            hops_area = d["FabricSettings"]["hops_area"]
            for h in hops_area:
                self.hops_area[int(h)] = hops_area[h]

            members = d["Participants"]
            for m in members:
                ports = members[m]["Ports"]
                for p in ports:
                    dp = p['switch']
                    ma = "00:00:%02x:00:00:%02x" % (dps[dp], p['Id'])
                    port = Port(m, p['Id'], dp , p['MAC'], p['IP'], ma)
                    self.ports.append(port)
                    sw = self.datapaths[dp]
                    sw.participants[m] = port


    def handle_broadcast(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        sw = self.datapaths[self.dpid_name[datapath.id]]
        inarea = sw.area
        bcast = "ff:ff:ff:ff:ff:ff"
        for p in self.ports:
            if p.switch == sw.name:
                # Always flood if in the same port
                match = parser.OFPMatch(eth_src=p.mac, eth_dst=bcast)
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 1000, inst, match, self.INGRESS_TABLE)    
            else:
                # When receiving from another switch, perform RFP
                # It means that it will only flood if src MAC comes from the 
                # path.
                dst_sw = self.datapaths[p.switch]
                path = self.all_paths[dst_sw.name][sw.name] #self.paths[inarea][dst_sw.name][sw.name]
                # Get what would be the hop before the switch in the path
                pre_hop = path[-2]
                #print path, pre_hop, sw
                for port in sw.ports:
                    if port[2] == pre_hop:
                        in_port = port[0]                    

                #in_port =   self.areas[inarea][sw.name][pre_hop]['ports'][sw.name]
                match = parser.OFPMatch(eth_src=p.mac, eth_dst=bcast, in_port=in_port)
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 1000, inst, match, self.INGRESS_TABLE)
    
    def add_ingress_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        insw = self.datapaths[self.dpid_name[datapath.id]]
        inarea = insw.area

        for p in self.ports:
            # Destination is in the same switch, forward directly
            if p.switch == insw.name:
                match = parser.OFPMatch(eth_dst=p.mac)
                actions = [parser.OFPActionOutput(p.id)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 100, inst, match, self.INGRESS_TABLE)
            else:
                # Install flow to rewrite destination MAC to moose MAC.
                out_sw = self.datapaths[p.switch]

                path = self.all_paths[insw.name][p.switch] #self.paths[inarea][insw.name][out_sw.name]
                out_sw = path[1]
                for port in self.datapaths[insw.name].ports:
                    sw = port[2]
                    if sw == out_sw:
                        out_port = port[0]
                        break
                #out_port = self.datapaths[insw.name].ports[out_sw] #self.areas[inarea][insw.name][path[1]]['ports'][insw.name]
                match = parser.OFPMatch(eth_dst=p.mac)
                actions = [parser.OFPActionSetField(eth_dst=p.moose_address), parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
                self.add_flow(datapath, 1000, inst, match, self.INGRESS_TABLE)

    def add_egress_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        insw = self.datapaths[self.dpid_name[datapath.id]]
        inarea = insw.area

        for p in self.ports:
            if p.switch == insw.name:
                match = parser.OFPMatch(eth_dst=p.moose_address)
                actions = [parser.OFPActionSetField(eth_dst=p.mac), parser.OFPActionOutput(p.id)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
                self.add_flow(datapath, 1000, inst, match, self.INGRESS_TABLE)

    def add_next_hops(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        sw = self.datapaths[self.dpid_name[datapath.id]]
        inarea = sw.area

        for s in self.datapaths:
            if s == sw.name:
                continue
            dst_sw = self.datapaths[s]
            # print dst_sw.label
            path = self.all_paths[sw.name][dst_sw.name] #self.paths[inarea][sw.name][dst_sw.name]
            
            for port in sw.ports:
                if port[2] == path[1]:
                    out_port = port[0] 
            #out_port = self.areas[inarea][sw.name][path[1]]['ports'][sw.name]

            match = parser.OFPMatch(eth_dst= ("%s:00:00:00" % dst_sw.label, "ff:ff:ff:00:00:00"))
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
            self.add_flow(datapath, 1000, inst, match, self.INGRESS_TABLE)

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
            self.add_flow(datapath, 10000, inst, match, self.HOP_AREA_TABLE)
            mask = [0] * 6
            mask[table] = 0xff
            mask_mac = ':'.join(map('{:02x}'.format, mask)).upper()
            # Add flow to deliver to participants in this switch
            for p in insw.participants:
                port =  insw.participants[p] 
                mac = [0] * 6
                mac[table] = port.id
                mac_addr = ':'.join(map('{:02x}'.format, mac)).upper()
                match = parser.OFPMatch(eth_dst=(mac_addr, mask_mac), vlan_vid=0x1000 | i)
                actions = [parser.OFPActionSetField(eth_dst=port.mac), parser.OFPActionPopVlan(), parser.OFPActionOutput(port.id)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 1000, inst, match, table)
            
            # Flows to forward to next hop of the path
            for port in insw.ports:
                mac = [0] * 6
                mac[table] = port[0]
                mac_addr = ':'.join(map('{:02x}'.format, mac)).upper()
                match = parser.OFPMatch(eth_dst=(mac_addr, mask_mac), vlan_vid=0x1000 | i)
                actions = []
                # If it is in the border, pop the vlan
                if port[1]:
                    actions.append(parser.OFPActionPopVlan())                  
                else:
                    # Increase the HOP count
                    actions.append(parser.OFPActionSetField(vlan_vid= 0x1000 | (i+1)))
                actions += [parser.OFPActionOutput(port[0])]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 10000, inst, match, table)

    def is_border(self, datapath):
        sw = self.datapaths[self.dpid_name[datapath.id]]
        return self.areas[sw.area].nodes[sw.name]["border"]

    def add_label_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        sw = self.datapaths[self.dpid_name[datapath.id]]
        
        # # Match the label, rewrite the MAC and send to ingress table 
        for port in self.ports:
            # TODO: Fix this awful idea to make the label. 
            # Perhaps work with bytes.
            al = str(hex( (0x1 << 12 | int(port.label))  ))
            head = ['0' + al[3], al[4:]]
            mac_addr = ':'.join(head) + ':' +':'.join(map('{:02x}'.format, [0]*4)).upper()
            mask = [0] * 6
            mask[0], mask[1] = (0x0f, 0xff)
            mask_mac = ':'.join(map('{:02x}'.format, mask)).upper()
            match = parser.OFPMatch(eth_dst=(mac_addr, mask_mac))
            actions = [parser.OFPActionSetField(eth_dst=port.mac)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            inst.append(parser.OFPInstructionGotoTable(self.INGRESS_TABLE))
            self.add_flow(datapath, 10000, inst, match, self.LABEL_TABLE)


    def add_border_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        sw = self.datapaths[self.dpid_name[datapath.id]]
        # Install flow to match area where packet comes from
        for area in self.areas:
            # in_port = self.borders[(sw.area, area)].src_port
            mac = mask = [0] * 6
            mac[0] = area << 4
            mac_addr = ':'.join(map('{:02x}'.format, mac)).upper()
            mask[0] = 0xf0
            mask_mac = ':'.join(map('{:02x}'.format, mask)).upper()
            match = parser.OFPMatch(eth_dst=(mac_addr, mask_mac))
            inst = [parser.OFPInstructionGotoTable(self.LABEL_TABLE)]
            self.add_flow(datapath, 5000, inst, match, self.HOP_AREA_TABLE)
        self.add_label_flows(datapath)


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
        self.handle_broadcast(datapath)
        self.add_egress_flows(datapath)
        self.add_next_hops(datapath)
        # if self.is_border(datapath):
            # self.add_border_flows(datapath)
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
