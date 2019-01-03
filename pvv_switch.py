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
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    PVV_TABLE = 1
    FAILURE_TABLE = 253
    # control plane 0 is OF, starting at table 2
    # control plane 1 is OSPF starting at table 100
    CP_TABLES = [2, 100]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        print "got from datapath", ev.datapath
        if ev.state == MAIN_DISPATCHER:
            print "main dispatcher, setting pvv rules"
            self.set_pvv_rules(ev.datapath, [1,0], 0)
        if ev.state == DEAD_DISPATCHER:
            print "dead dispatcher"
        if ev.state == HANDSHAKE_DISPATCHER:
            print "handshake dispatcher"
        if ev.state == CONFIG_DISPATCHER:
            print "config dispatcher"



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
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
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
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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

    # preferences is a list of control planes in order
    # availabilities is an integer representation of available protocols
    #   in the same format of PVV
    #   (1 if UNAVAILABLE, 0 if available).
    def set_pvv_rules(self, datapath, preferences, availabilities):
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # get the packet info
        for current_cp in preferences:
            # 2^k iterations, one for each PVV. Should be able to wildcard
            # this later
            for pvv_match in xrange(2**len(preferences)):

                match = ofproto_parser.OFPMatch(
                    vlan_vid=(0x1000 | pvv_match),
                    vlan_pcp=current_cp)

                usable = pvv_match | availabilities

                # go through the preferences
                # protocol numbers will be 0-indexed in the preferences list,
                # and protocol 0 will be the least significant bit in the pvv
                # this loop to find the best usable cp
                best_cps = []
                for cp in preferences:
                    mask = 1 << cp
                    if cp == current_cp or (mask & usable) == 0:
                        best_cps.append(cp)
                        if len(best_cps) == 2:
                            break

                t1_actions = []
                failure_actions = []
                to_controller_action = ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)

                if len(best_cps) == 0:
                    # all flow rules should just be to send to controller
                    t1_actions.append(to_controller_action)
                    failure_actions.append(to_controller_action)


                else:
                    t1_cp = best_cps[0]

                    # if the best_cp is NOT the same as current_cp, then we need to also rewrite the
                    # PVV/current_cp tags
                    if t1_cp != current_cp:
                        mask = 1 << t1_cp
                        new_pvv = pvv_match | mask
                        t1_actions.append(
                                ofproto_parser.OFPActionSetField(vlan_vid=(0x1000 | new_pvv))
                                )
                        t1_actions.append(
                                ofproto_parser.OFPActionSetField(vlan_pcp=t1_cp)
                                )


                    t1_actions.append(ofproto_parser.NXActionResubmitTable(table_id=self.CP_TABLES[t1_cp]))

                    if len(best_cps) == 1:
                        failure_actions.append(to_controller_action)
                    else:
                        failure_cp = best_cps[1]
                        failure_actions.append(ofproto_parser.NXActionResubmitTable(table_id=self.CP_TABLES[failure_cp]))

                        # if the failure table action goes to a different control plane from current_cp,
                        # then we need to rewrite the PVV headers
                        if failure_cp != current_cp:
                            mask = 1 << failure_cp
                            new_pvv = pvv_match | mask
                            failure_actions.append(
                                    ofproto_parser.OFPActionSetField(vlan_vid=(0x1000 | new_pvv))
                            )
                            failure_actions.append(
                                    ofproto_parser.OFPActionSetField(vlan_pcp=failure_cp)
                            )

                # now we send teh message to the datapath. table id 0 is reserved for t1
                t1_mod = ofproto_parser.OFPFlowMod(
                    datapath,
                    table_id=self.PVV_TABLE,
                    command=datapath.ofproto.OFPFC_ADD,
                    match=match,
                    instructions=[ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions=t1_actions)])

                failure_mod = ofproto_parser.OFPFlowMod(
                    datapath,
                    table_id=self.FAILURE_TABLE,
                    command=datapath.ofproto.OFPFC_ADD,
                    match=match,
                    instructions=[ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions=failure_actions)])

                print "sending message for t1 and failure tables"
                datapath.send_msg(t1_mod)
                datapath.send_msg(failure_mod)
