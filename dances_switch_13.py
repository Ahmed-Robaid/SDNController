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


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def limit_flow(self, datapath, hw_mac=""):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        ## port_no = ofp.OFPP_ANY
        ## config = 0

        ## mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV | ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)
        ## advertise = (ofp.OFPPF_10MB_HD)

        ## req = ofp_parser.OFPPortMod(datapath, port_no, hw_mac, config, mask, advertise)
        port_no = ofp.OFPP_ANY
        req = ofp_parser.OFPQueueGetConfigRequest(datapath, port_no)
        datapath.send_msg(req)

    def portstats(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortStatsRequest(datapath, ofp.OFPMPF_REQ_MORE, ofp.OFPP_ANY)
        datapath.send_msg(req)

    def get_port(self, datapath):
        for port_no, port in datapath.ports.items():
            if port_no != dp.ofproto.OFPP_LOCAL:
                return port
        return None

    ## @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    ## def port_desc_stats_reply_handler(self, ev):
    ##     ports = []

    ##     msg = ev.msg
    ##     datapath = msg.datapath
    ##     ofproto = datapath.ofproto
    ##     parser = datapath.ofproto_parser
    ##     ## So, when we ask for port descriptions, we want to add a flow
    ##     ## for that port (so, all ports)
    ##     for p in ev.msg.body:
    ##         ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
    ##                      'state=0x%08x curr=0x%08x advertised=0x%08x '
    ##                      'supported=0x%08x peer=0x%08x curr_speed=%d '
    ##                      'max_speed=%d' %
    ##                      (p.port_no, p.hw_addr,
    ##                       p.name, p.config,
    ##                       p.state, p.curr, p.advertised,
    ##                       p.supported, p.peer, p.curr_speed,
    ##                       p.max_speed))
    ##         in_port = msg.match[p.name]
    ##         self.logger.debug("Adding flow for: %s", in_port)

    ##         actions = [parser.OFPActionSetQueue(123)]
    ##         match = parser.OFPMatch(in_port=in_port)
    ##         self.add_flow(datapath, 1, match, actions)
    ##         self.logger.debug("Flow added")

    ##     self.logger.debug('OFPPortDescStatsReply received: %s', ports)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

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

        ## Set up a QoS for traffic from host1
        if src == "00:00:00:00:00:01":
            actions = [parser.OFPActionSetQueue(123), parser.OFPActionOutput(out_port)]
        else:
            actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        

##     @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
##     def port_desc_stats_reply_handler(self, ev):
##         ports = []
##         for p in ev.msg.body:
##             ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
##                          'state=0x%08x curr=0x%08x advertised=0x%08x '
##                          'supported=0x%08x peer=0x%08x curr_speed=%d '
##                          'max_speed=%d' %
##                          (p.port_no, p.hw_addr,
##                           p.name, p.config,
##                           p.state, p.curr, p.advertised,
##                           p.supported, p.peer, p.curr_speed,
##                           p.max_speed))
##         self.logger.debug('OFPPortDescStatsReply received: %s', ports)

