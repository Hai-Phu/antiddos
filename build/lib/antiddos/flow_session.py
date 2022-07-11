import csv
from collections import defaultdict

import numpy as np
import pickle
from scapy.sessions import DefaultSession
from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow
from .network import MLP_Network
import threading
import logging
import os
from os.path import exists
import ftplib
import getpass
import sys
import time
import socket
from cymruwhois import Client

# root = logging.getLogger()
# root.setLevel(logging.DEBUG)

# logging.basicConfig(
#     level=logging.DEBUG,
#     filemode='w',
#     filename='/var/log/antiddos.log',
#     format="%(asctime)s: Antiddos: %(message)s",
# )

logFormatter = logging.Formatter("%(asctime)s: Antiddos: %(message)s")
rootLogger = logging.getLogger()

fileHandler = logging.FileHandler('/var/log/antiddos.log')
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)


FTP_FILE="/etc/antidos/user.py"
def get_info_ftp():
    with open(FTP_FILE, "a") as file_object:
# Append 'hello' at the end of file
        
        server = input("Please enter the FTP server: ")
        server = "SERVER = " + "'" + server + "'" + "\n"
        file_object.write(server)
        user = input("Please enter user name: ")
        user = "USER = " + "'" + user + "'" +"\n"
        file_object.write(user)
        password = getpass.getpass("Please enter password: ")
        password = "PASSWORD = " + "'" + password + "'" + "\n"
        file_object.write(password)

while True:
    try:
        file_exists = exists(FTP_FILE)
        if file_exists==False:
            create_ftp_login = "touch "+FTP_FILE
            os.system(create_ftp_login)
            get_info_ftp()
        sys.path.insert(1, "/etc/antidos")
        import user
        HOSTNAME = user.SERVER
        USERNAME = user.USER
        PASSWORD = user.PASSWORD
        ftp_test = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
        logging.error("FTP Server connection SUCCESSFUL")
        break
    except OSError as error:
        if error.args[0] == 113:
            logging.error("FTP server not Responding!!!")
            break
        else:
            # os.remove("/etc/antidos/user.py")
            logging.error("FTP Server connection get FAILED!!!")



EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100
# MODEL='/etc/antidos/model.sav'

BLACKLIST='/etc/antidos/blacklist'
WHITELIST='/etc/antidos/whitelist'

FEATURES=["flow_duration","fwd_pkt_len_max",
          "fwd_pkt_len_min","fwd_pkt_len_std","flow_iat_mean",
          "flow_iat_max", "fwd_iat_mean","fwd_iat_max",
          "fwd_header_len","fwd_pkts_s", "pkt_len_min",
          "pkt_len_max","pkt_len_std","ack_flag_cnt","pkt_size_avg",
          "subflow_fwd_pkts","init_fwd_win_byts","fwd_seg_size_min"]

CHECKASN = {'google','facebook','youtube','amazon','microsoft',
            'shopee','fpt','vietel','vnpt','vng','telegram',
            'valve','opera','alibaba','cloudflarenet','fastly',
            'vietcombank','cmctelecom','saigon','wikimedia','cloud'}

class FlowSession(DefaultSession):
    """Creates a list of network flows."""
    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        self.i=0
        self.countlog = 0
        self.first = 0
        self.second = 0
        self.third = 0
        output = open(self.output_file, "w")
        self.csv_writer = csv.writer(output)
        self.wait_server = False

        self.packets_count = 0
        try:
            self.ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
            # logging.error("FTP Server connection SUCCESSFUL")
            self.ftp_server.encoding = "utf-8"
            self.ftp_connected = True
        except:
            self.ftp_connected = False
        self.clumped_flows_per_label = defaultdict(list)
        self.layers = [40,40,6]
        self.model = MLP_Network(layers = self.layers, weight_file = '/etc/antidos/weight.npz')
        super(FlowSession, self).__init__(*args, **kwargs)
        WHITELIST = [line.rstrip() for line in open('/etc/antidos/wwl.txt','r')]
        for website in WHITELIST:
            IP_address = socket.gethostbyname(website)
            with open('/etc/antidos/whitelist') as wl: 
                if not IP_address in wl.read() :
                    fa=open('/etc/antidos/whitelist', "a")
                    fa.write("\n")
                    fa.write(IP_address)

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

    # def attack_type(self,x):
    #         switcher={
    #                 0:'Benign',
    #                 1:'LDAP',
    #                 2:'MSSQL',
    #                 3:'NetBIOS',
    #                 4:'UDP',
    #                 5:'Syn',        
    #         }
    #         return switcher.get(x, "Unknown")

    def check_ftp_sever(self):
        try:
            if self.ftp_connected:
                self.ftp_server.getwelcome()
            else:
                self.ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
                logging.error("FTP Server connection SUCCESSFUL")
                self.ftp_connected = True
            ftp_live = True
        except:
            self.countlog+=1
            if (self.countlog % 88) == 0:
                logging.error("FTP server not Responding!!!")
                self.countlog=0
            ftp_live = False
        return ftp_live

    def garbage_collect(self, latest_time) -> None:
        keys = list(self.flows.keys())
        flag = 0
        self.wait_server = True
        if self.wait_server == True:
            if self.check_ftp_sever():
                for file in self.ftp_server.nlst('files'):
                    if file == 'files/update_available':
                        with open("/etc/antidos/weight.npz", 'wb' ) as file :
                            logging.error("Weights are being loaded .....")
                            self.ftp_server.delete('files/update_available')
                            self.ftp_server.retrbinary('RETR files/weight.npz', file.write)
                            flag = 1
                            self.wait_server=False
                if flag == 1:       
                    self.model = MLP_Network(layers = self.layers, weight_file = '/etc/antidos/weight.npz')
                    logging.error("Model has been updated!")
                    
        for k in keys:
            flow = self.flows.get(k)
            
            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
                data = flow.get_data()
                c = Client()
                try:
                    asn = c.lookup(data["src_ip"]).owner
                except TypeError:
                    asn = 'na'
                except:
                    asn = 'na'
                for anscheck in CHECKASN:
                    if anscheck in asn.lower():
                        ignore = 1
                        break
                    else:
                        ignore = 0
                x=np.array(list(map(data.get, FEATURES))).reshape(1,18)
                x[np.isnan(x)] = 0
                # x = (x-self.x_min)/(self.x_max-self.x_min)
                # a=a.reshape(-1, 1)
                label = self.model.predict(x)
                # print(data["src_ip"])
                # print(label)
                if ignore == 0:
                    # print(asn.lower())
                    if label!=[0.]:
                        with open('/etc/antidos/whitelist') as wl:  
                            if not data["src_ip"] in wl.read() :
                                with open('/etc/antidos/blacklist') as bl:
                                    if not data["src_ip"] in bl.read() :
                                        fa = open('/etc/antidos/blacklist', "a")
                                        fa.write(data["src_ip"])
                                        fa.write("\n")
                                    os.system("/etc/init.d/antiddos reload")
                                    if "192.168.1." in data["src_ip"]:
                                        if "192.168.1." in data["src_ip"]:
                                            self.first = self.second
                                            self.second = self.third
                                            self.third = time.time()
                                            if (self.third - self.first) < 10 and (self.first != 0):
                                                logging.error('Your device is attacked with source IP: %s destination IP: %s'%((data["src_ip"]),(data["dst_ip"])))

                                    else:
                                        logging.error('Your device is attacked with source IP: %s destination IP: %s'%((data["src_ip"]),(data["dst_ip"])))
                    
                    with open('/etc/antidos/whitelist') as wl:  
                        if not data["src_ip"] in wl.read() :
                            if self.csv_line == 0:
                                self.csv_writer.writerow(data.keys())
                            if label == [0.]:                      
                                self.csv_writer.writerow(data.values())
                                self.csv_line += 1
                                if (self.csv_line % 500)==0:
                                    if self.check_ftp_sever():
                                        i=0
                                        self.csv_line = 0
                                        for file in self.ftp_server.nlst('files/flows'):
                                            filename='files/flows/flow'+str(i)+".csv"
                                            i+=1
                                            if file != filename:
                                                break
                                        filenamesave='files/flows/flow'+str(i)+".csv"
                                        logging.error("Sending benign flow to an FTP Server and request an update...")
                                        with open(self.output_file, "rb") as file:
                                            self.ftp_server.storbinary(f"STOR {filenamesave}", file) 
                                        
                                        os.system("touch /etc/antidos/update_required")
                                        file1 = open("/etc/antidos/update_required","a")
                                        file1.write(USERNAME)
                                        file1.close()
                                        with open("/etc/antidos/update_required", "rb") as file:
                                            self.ftp_server.storbinary(f"STOR files/update_required", file)                         
                                        os.remove("/etc/antidos/update_required")
                                        os.remove(self.output_file)
                                        self.wait_server=True
                                        output = open(self.output_file, "w")
                                        self.csv_writer = csv.writer(output)
                                        


                del self.flows[k]
                return x

        # if not self.url_model:
        #     logging.info("Garbage Collection Finished. Flows = {}".format(len(self.flows)))


def generate_session_class(output_file):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_file": output_file,
        },
    )
