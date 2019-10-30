#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import RemoteController, OVSSwitch
from sdnip import BgpRouter, SdnipHost

ROUTE_SERVER_IP = '172.0.0.254'
ROUTE_SERVER_ASN = 65000


class SDXTopo( Topo ):
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        # Describe Code
        # Set up data plane switch - this is the emulated router dataplane
        # Note: The controller needs to be configured with the specific driver that
        # will be attached to this switch.

        # IXP fabric
        # Ring -> Area 1
        ld5 = self.addSwitch('ld5')
        ld4 = self.addSwitch('ld4')
        ld10 = self.addSwitch('ld10')
        ld6 = self.addSwitch('ld6')

        self.addLink(ld4, ld10, 1, 1)
        self.addLink(ld4, ld5, 2, 1)
        self.addLink(ld6, ld10, 1, 2)
        self.addLink(ld6, ld5, 2, 2)
 
        # Edge Core -> Area 2
        eq_harbour = self.addSwitch('eq_har1')
        interxion = self.addSwitch('inter2')
        dr = self.addSwitch('dr3')
        eq_pg = self.addSwitch('eq_pg7')

        self.addLink(eq_pg, eq_harbour, 1, 1)
        self.addLink(eq_pg, interxion, 2, 1)
        self.addLink(dr, eq_harbour, 1, 2)
        self.addLink(dr, interxion, 2, 2)
        self.addLink(eq_harbour, interxion, 3, 3)

        # Ring -> Area 3
        th_west = self.addSwitch('th_west8')
        th_north = self.addSwitch('th_north9')
        sovereign = self.addSwitch('sv11')

        self.addLink(sovereign, th_west, 1, 1)
        self.addLink(sovereign, th_north, 2, 1)
        self.addLink(th_west, th_north, 2, 2)

        # Connect Areas
        self.addLink(ld10, th_north, 3, 3)
        self.addLink(ld10, eq_harbour, 4, 4)
        self.addLink(eq_harbour, th_north, 5, 4)
        self.addLink(interxion, th_west, 4, 3)


        # Add node for central Route Server"
        route_server = self.addHost('rs1', ip = '172.0.0.254/24', mac='08:00:27:89:3b:ff', inNamespace = False)
        self.addLink(dr, route_server, 3)

        
        # Add Participants to the IXP (one for each edge switch)

        self.addParticipant(fabric=ld4,
                            name="a1",
                            port=3,
                            mac="00:00:00:00:00:01",
                            ip="172.0.0.1/24",
                            networks=["172.1.0.0/16", "172.2.0.0/16"],
                            asn=100)

        self.addParticipant(fabric=ld6,
                            name="b1",
                            port=3,
                            mac="00:00:00:00:00:02",
                            ip="172.0.0.11/24",
                            networks=["172.9.25.0/24", "172.9.96.0/24"],
                            asn=200)

        self.addParticipant(fabric=th_north,
                            name="c1",
                            port=5,
                            mac="00:00:00:00:00:03",
                            ip="172.0.0.21/24",
                            networks=["172.3.0.0/16", "172.4.0.0/16"],
                            asn=300)

        self.addParticipant(fabric=th_west,
                            name="d1",
                            port=4,
                            mac="00:00:00:00:00:04",
                            ip="172.0.0.22/24",
                            networks=["172.5.0.0/16", "172.8.0.0/16"],
                            asn=400)

        self.addParticipant(fabric=ld5,
                            name="e1",
                            port=3,
                            mac="00:00:00:00:00:05",
                            ip="172.0.0.23/24",
                            networks=["172.15.0.0/16", "172.18.0.0/16"],
                            asn=500)

        self.addParticipant(fabric=dr,
                            name="f1",
                            port=4,
                            mac="00:00:00:00:00:06",
                            ip="172.0.0.24/24",
                            networks=["172.25.0.0/16", "172.28.0.0/16"],
                            asn=600)

    def addParticipant(self, fabric, name, port, mac, ip, networks, asn):
        # Adds the interface to connect the router to the Route server
        peereth0 = [{'mac': mac, 'ipAddrs': [ip]}]
        intfs = {name + '-eth0': peereth0}

        # Adds 1 gateway interface for each network connected to the router
        for net in networks:
            eth = {'ipAddrs': [replace_ip(net, '254')]}  # ex.: 100.0.0.254
            i = len(intfs)
            intfs[name + '-eth' + str(i)] = eth

        # Set up the peer router
        neighbors = [{'address': ROUTE_SERVER_IP, 'as': ROUTE_SERVER_ASN}]
        peer = self.addHost(name,
                            intfDict=intfs,
                            asNum=asn,
                            neighbors=neighbors,
                            routes=networks,
                            cls=BgpRouter)
        self.addLink(fabric, peer, port)

        # Adds a host connected to the router via the gateway interface
        i = 0
        for net in networks:
            i += 1
            ips = [replace_ip(net, '1')]  # ex.: 100.0.0.1/24
            hostname = 'h' + str(i) + '_' + name  # ex.: h1_a1
            host = self.addHost(hostname,
                                cls=SdnipHost,
                                ips=ips,
                                gateway=replace_ip(net, '254').split('/')[0])  # ex.: 100.0.0.254
            # Set up data plane connectivity
            self.addLink(peer, host)

def replace_ip(network, ip):
    net,subnet=network.split('/')
    gw=net.split('.')
    gw[3]=ip
    gw='.'.join(gw)
    gw='/'.join([gw,subnet])
    return gw

if __name__ == "__main__":
    setLogLevel('info')
    topo = SDXTopo()

    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch)

    net.start()

    CLI(net)

    net.stop()
