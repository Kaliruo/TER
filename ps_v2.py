import pyshark
import csv
import sys
import time 
from statistics import pstdev

class StreamStats:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, transport_protocol, application_protocol):
        self.transport_protocol = transport_protocol
        self.application_protocol = application_protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.packets = []
        self.packet_count = 0
        self.up_packets = 0
        self.down_packets = 0
        self.bytes = 0
        self.bytes_up =0
        self.bytes_down=0
        self.duration = 0
        self.packet_sizes = []
        self.ecart_type =0
    
    #ajoute un paquet a un flux et met a jour certains paramètres
    def add_packet(self, packet):
        self.packets.append(packet)
        self.packet_count += 1
        packet_size = 0
        if self.transport_protocol == 'UDP':
            packet_size = int(packet['udp'].length)
            self.bytes += packet_size
            if packet['ip'].src == self.src_ip and packet['ip'].dst == self.dst_ip:
                self.up_packets += 1
                self.bytes_up += packet_size
            else:
                self.down_packets += 1
                self.bytes_down += packet_size
        elif self.transport_protocol == 'TCP':
            packet_size = int(packet['tcp'].len)
            self.bytes += packet_size
            if packet['ip'].src == self.src_ip and packet['ip'].dst == self.dst_ip:
                self.up_packets += 1
                self.bytes_up += packet_size
            else:
                self.down_packets += 1
                self.bytes_down += packet_size
        
        self.packet_sizes.append(packet_size)
    
    #Pour afficher les données d'un flux
    def __str__(self):
        return f"==== Stream Statistics ====\n" \
               f"Application Protocol: {self.application_protocol}\n" \
               f"Transport Protocol: {self.transport_protocol}\n" \
               f"Source IP: {self.src_ip}:{self.src_port}\n" \
               f"Destination IP: {self.dst_ip}:{self.dst_port}\n" \
               f"Source Port: {self.src_port}\n" \
               f"Destination Port: {self.dst_port}\n" \
               f"Packet Count: {self.packet_count}\n" \
               f"UDP Packets (Up): {self.up_packets}\n" \
               f"UDP Packets (Down): {self.down_packets}\n" \
               f"TCP Bytes: {self.bytes}\n" \
               f"===========================\n"
    
    #pour la durée
    def set_duration(self):
        if self.packet_count > 0:
            start_time = self.packets[0].sniff_time
            end_time = self.packets[-1].sniff_time
            self.duration = end_time - start_time
        return self.duration.total_seconds()

    #pour l'écart type
    def set_ecart_type(self):
        if self.packet_count > 0:
            self.ecart_type = pstdev(self.packet_sizes)
        return self.ecart_type

# fonction qui va lire le fichier paquet par paquet et les regrouper par flux
def analyze_pcap_file(filename):
    capture = pyshark.FileCapture(filename)
    stream_stats = {}
    compteur=0
    for packet in capture:
        compteur+=1
        http = True #pour vérifier si c'est bien http
        if 'ip' in packet:
            src_ip = packet['ip'].src
            dst_ip = packet['ip'].dst

            if 'udp' in packet:
                src_port = packet['udp'].srcport
                dst_port = packet['udp'].dstport
                transport_protocol = 'UDP'
                if 'quic' in packet:
                    application_protocol = 'HTTP/3 - QUIC'
                else:
                    http=False
            elif 'tcp' in packet:
                src_port = packet['tcp'].srcport
                dst_port = packet['tcp'].dstport
                transport_protocol = 'TCP'
                if 'tls' in packet and (src_port == '443' or dst_port == '443'):
                    application_protocol = 'HTTP/2 - TLS'
                elif src_port == '80' or dst_port == '80':
                    application_protocol = 'HTTP/1.1'
                else:
                    http=False
            else:
                http=False
            
            if http==True:       
                stream_id_1 = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                stream_id_2 = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

                #on teste si le flux existe déja dans un sens ou l'autre
                if stream_id_1 in stream_stats:
                    stream_stats[stream_id_1].add_packet(packet)
                elif stream_id_2 in stream_stats:
                    stream_stats[stream_id_2].add_packet(packet)
                else:
                    stream_stats[stream_id_1] = StreamStats(src_ip, dst_ip, src_port, dst_port, transport_protocol,
                                                        application_protocol)
                    stream_stats[stream_id_1].add_packet(packet)

    return stream_stats

#Fonction qui écrit les données sur les flux dans un fichier csv
def write_csv(stats, output_file):
    with open(output_file, 'w',newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([ "Port 1","Port 2","Packet Count", " Packets (Up)", " Packets (Down)", "Average Bytes/packet",
                            "Average bytes up","Average bytes down","Total bytes","Duration (seconds)","écart-type"])
        for stream_id, stream_stats in stats.items():
            #pour eviter la division par zero
            if stream_stats.up_packets ==0:
                average_bytes_up=0
            else :
                average_bytes_up = int(stream_stats.bytes_up/stream_stats.up_packets)

            if stream_stats.down_packets ==0:
                average_bytes_down=0
            else :
                average_bytes_down = int(stream_stats.bytes_down/stream_stats.down_packets)

            writer.writerow([ stream_stats.src_port,stream_stats.dst_port, stream_stats.packet_count,
                             stream_stats.up_packets, stream_stats.down_packets, int(stream_stats.bytes/stream_stats.packet_count),
                             average_bytes_up, average_bytes_down,stream_stats.bytes, stream_stats.set_duration(), stream_stats.set_ecart_type() ])


debut = time.time()

filename = sys.argv[1]
#le nom du fichier de sortie csv et le meme que le fichier pcap d'entré
output_file = "csv/"+filename[8:len(filename)-7]+'.csv'
print(output_file)


stream_stats = analyze_pcap_file(filename)
write_csv(stream_stats, output_file)


fin= time.time()
print("temsp  : ", fin - debut," secondes")