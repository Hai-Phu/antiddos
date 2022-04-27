import csv
from collections import defaultdict

import numpy as np
import pickle
from scapy.sessions import DefaultSession
from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow
from .network import MLP_Network

import logging
import os
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(filename)s[%(funcName)s]: %(message)s",
    handlers=[
        logging.FileHandler("sniffer.log"),
        logging.StreamHandler()
    ]
)

EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100
MODEL='/etc/antidos/model.sav'

BLACKLIST='/etc/antidos/blacklist'
WHITELIST='/etc/antidos/whitelist'

FEATURES=["protocol","flow_duration","tot_fwd_pkts","tot_bwd_pkts","totlen_fwd_pkts","totlen_bwd_pkts","fwd_pkt_len_max",
          "fwd_pkt_len_min","fwd_pkt_len_mean","fwd_pkt_len_std","bwd_pkt_len_max","bwd_pkt_len_min","bwd_pkt_len_mean",
          "bwd_pkt_len_std","flow_byts_s","flow_pkts_s","flow_iat_mean","flow_iat_std","flow_iat_max",
          "flow_iat_min","fwd_iat_tot","fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min","bwd_iat_tot",
          "bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min","fwd_header_len","bwd_header_len","fwd_pkts_s",
          "bwd_pkts_s","pkt_len_min","pkt_len_max","pkt_len_mean","pkt_len_std","pkt_len_var","down_up_ratio",
          "pkt_size_avg","init_fwd_win_byts","init_bwd_win_byts","fwd_seg_size_min","fwd_act_data_pkts","active_mean",
          "active_std","active_max","active_min","idle_mean","idle_std","idle_max","idle_min"]

class FlowSession(DefaultSession):
    """Creates a list of network flows."""
    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        if self.output_file is not None:
            output = open(self.output_file, "w")
            self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)
        layers = [53,40,30]
        self.model = MLP_Network(layers = layers, weight_file = '/etc/antidos/weight.pkl')

        super(FlowSession, self).__init__(*args, **kwargs)



    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD
        
        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        elif "F" in str(packet.flags):
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(packet, direction)
            self.garbage_collect(packet.time)
            return

        flow.add_packet(packet, direction)

        # if not self.url_model:
        #     GARBAGE_COLLECT_PACKETS = 10000

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_file is not None
        ):
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:

        keys = list(self.flows.keys())
        
        for k in keys:
            flow = self.flows.get(k)
            
            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
                data = flow.get_data()
                x=np.array(list(map(data.get, FEATURES))).reshape(1,53)
                x[np.isnan(x)] = 0
                
                # a=a.reshape(-1, 1)
                if self.model.predict(x)!=[0.]:
                    with open('/etc/antidos/blacklist') as f:
                        if not data["src_ip"] in f.read():
                            fa = open('/etc/antidos/blacklist', "a")
                            fa.write(data["src_ip"])
                            fa.write("\n")
                            print('WARNING: your device is attacked by a device using IP address: %s'%(data["src_ip"]))
                else:
                    with open('/etc/antidos/whitelist') as f:
                        if not data["src_ip"] in f.read():
                            fa = open('/etc/antidos/whitelist', "a")
                            fa.write(data["src_ip"])
                            fa.write("\n")                         

                # print(a)
                # print(a.shape)
                
                if self.output_file is not None:
                    if self.csv_line == 0:
                        self.csv_writer.writerow(data.keys())

                    self.csv_writer.writerow(data.values())
                    self.csv_line += 1

                del self.flows[k]
                return x

        # if not self.url_model:
        #     print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))


def generate_session_class(output_file):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_file": output_file,
        },
    )
