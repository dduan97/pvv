"""
    Packet headers used for PVV:
        - vlan_vid for PVV vector
        - vlan_pcp for current protocol tag

    Need switches to support NX extensions as well as OF 1.2 or later

    One edge case:
        - packet comes in with PVV=011 and current_cp=2
        - t0 matches and forwards to control plane 0, setting PVV=101 and current_cp=0
        - control plane 0 is unavailable, sending packet to failure table
        - failure table matches on PVV=111 and current_cp=0, but no protocols are available
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.controller import dpset



class PVVSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(PVVSwitch, self).__init__(*args, **kwargs)



    # @set_ev_cls(ofp_event.EventOFPPacketIn, [MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER])
    # def _packet_in_handler(self, ev):
        # msg = ev.msg
        # datapath = msg.datapath
        # ofproto = datapath.ofproto


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


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

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
                    vlan_vid=pvv_match,
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

                t0_actions = []
                failure_actions = []
                to_controller_action = ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)

                if len(best_cps) == 0:
                    # all flow rules should just be to send to controller
                    t0_actions.append(to_controller_action)
                    failure_actions.append(to_controller_action)


                else:
                    t0_cp = best_cps[0]

                    # if the best_cp is NOT the same as current_cp, then we need to also rewrite the
                    # PVV/current_cp tags
                    if t0_cp != current_cp:
                        mask = 1 << t0_cp
                        new_pvv = pvv_match | mask
                        t0_actions.append(
                                ofproto_parser.OFPActionSetField(vlan_vid=new_pvv)
                                )
                        t0_actions.append(
                                ofproto_parser.OFPActionSetField(vlan_pcp=t0_cp)
                                )


                    # flow rule action should be to forward to the table for t0_cp
                    # since table 0 is reserved for PVV, control plane k will have table
                    # k+1 (for now)
                    t0_actions.append(ofproto_parser.NXActionResubmitTable(table_id=t0_cp+1))

                    if len(best_cps) == 1:
                        failure_actions.append(to_controller_action)
                    else:
                        failure_cp = best_cps[1]
                        failure_actions.append(ofproto_parser.NXActionResubmitTable(table_id=failure_cp+1))

                        # if the failure table action goes to a different control plane from current_cp,
                        # then we need to rewrite the PVV headers
                        if failure_cp != current_cp:
                            mask = 1 << failure_cp
                            new_pvv = pvv_match | mask
                            failure_actions.append(
                                    ofproto_parser.OFPActionSetField(vlan_vid=new_pvv)
                            )
                            failure_actions.append(
                                    ofproto_parser.OFPActionSetField(vlan_pcp=failure_cp)
                            )

                # now we send teh message to the datapath. table id 0 is reserved for t0
                t0_mod = ofproto_parser.OFPFlowMod(
                    datapath,
                    table_id=0,
                    command=datapath.ofproto.OFPFC_ADD,
                    match=match,
                    instructions=[ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions=t0_actions)])

                # for now, let's say the failure table is id 255
                failure_mod = ofproto_parser.OFPFlowMod(
                    datapath,
                    table_id=255,
                    command=datapath.ofproto.OFPFC_ADD,
                    match=match,
                    instructions=[ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions=failure_actions)])

                print "sending message for t0 and failure tables"
                datapath.send_msg(t0_mod)
                datapath.send_msg(failure_mod)

