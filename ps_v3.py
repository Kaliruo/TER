import pyshark
import csv
import sys
import time 
import os 
import hashlib
from statistics import pstdev


# Vérifier si le dossier "csv" existe, sinon le créer
if not os.path.exists("csv"):
    os.makedirs("csv")

# Vérifier si le dossier "key" existe, sinon le créer
if not os.path.exists("key"):
    os.makedirs("key")


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
        self.ecart_type = 0
        self.packet_time_up =[]
        self.packet_time_down =[]
    
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
                self.packet_time_up.append(packet.sniff_time)
            else:
                self.down_packets += 1
                self.bytes_down += packet_size
                self.packet_time_down.append(packet.sniff_time)
        elif self.transport_protocol == 'TCP':
            packet_size = int(packet['tcp'].len)
            self.bytes += packet_size
            if packet['ip'].src == self.src_ip and packet['ip'].dst == self.dst_ip:
                self.up_packets += 1
                self.bytes_up += packet_size
                self.packet_time_up.append(packet.sniff_time)
            else:
                self.down_packets += 1
                self.bytes_down += packet_size
                self.packet_time_down.append(packet.sniff_time)
        
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
        return "{:.2f}".format(self.duration.total_seconds())

    #pour l'écart type
    def set_ecart_type(self):
        if self.packet_count > 0:
            self.ecart_type = pstdev(self.packet_sizes)
        return "{:.2f}".format(self.ecart_type)

    #pour le temps moyen inter-paquets
    def set_inter_packet_time_mean_up(self):
        if self.up_packets > 1:
            duration =(self.packet_time_up[-1] - self.packet_time_up[0]).total_seconds()
            return "{:.2f}".format(duration / (self.up_packets - 1))

        #total_inter_packet_time = 0
        #prev_packet = self.packets[0].sniff_time
        #for packet in self.packets[1:]:
            #current_packet = packet.sniff_time
            #inter_time = (current_packet - prev_packet).total_seconds()
            #total_inter_packet_time += inter_time
            #prev_packet = current_packet

        return 0

    def set_inter_packet_time_mean_down(self):
        if self.down_packets > 1:
            duration =(self.packet_time_down[-1] - self.packet_time_down[0]).total_seconds()
            return "{:.2f}".format(duration / (self.down_packets - 1))

        #total_inter_packet_time = 0
        #prev_packet = self.packets[0].sniff_time
        #for packet in self.packets[1:]:
            #current_packet = packet.sniff_time
            #inter_time = (current_packet - prev_packet).total_seconds()
            #total_inter_packet_time += inter_time
            #prev_packet = current_packet

        return 0

    # pour l'écart-type des temps inter-paquets des paquets up
    def set_inter_packet_time_ecart_type_up(self):
        if self.up_packets > 1:
            inter_packet_times = []
            prev_packet = self.packet_time_up[0]
            for packet in self.packet_time_up[1:]:
                inter_packet_times.append((packet - prev_packet).total_seconds())
                prev_packet = packet
            return "{:.2f}".format(pstdev(inter_packet_times))
        return 0

    # pour l'écart-type des temps inter-paquets des paquets down
    def set_inter_packet_time_ecart_type_down(self):
        if self.down_packets > 1:
            inter_packet_times = []
            prev_packet = self.packet_time_down[0]
            for packet in self.packet_time_down[1:]:
                inter_packet_times.append((packet - prev_packet).total_seconds())
                prev_packet = packet
            return "{:.2f}".format(pstdev(inter_packet_times))
        return 0

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
def write_csv(stats, output_data,output_key):
    with open(output_data, 'w',newline='') as data_file:
        writer = csv.writer(data_file)
        writer.writerow([ "Stream ID","Packet Count", " Packets (Up)", " Packets (Down)", "Average Bytes/packet",
                          "Average bytes up","Average bytes down","Total bytes","Duration (seconds)","écart-type (bytes)",
                          "Average inter packet time up","Average inter packet time down","ecart-type temps inter paquet up","ecart-type temps inter paquet down"])
        for stream_id, stream_stats in stats.items():
            #pour eviter la division par zero
            if stream_stats.packet_count >= 10:
                Hash_ID=hashlib.sha256(f"{stream_id}-{stream_stats.transport_protocol}".encode()).hexdigest()
                if stream_stats.up_packets ==0:
                    average_bytes_up=0
                else :
                    average_bytes_up = int(stream_stats.bytes_up/stream_stats.up_packets)

                if stream_stats.down_packets ==0:
                    average_bytes_down=0
                else :
                    average_bytes_down = int(stream_stats.bytes_down/stream_stats.down_packets)

                writer.writerow([ Hash_ID, stream_stats.packet_count,
                              stream_stats.up_packets, stream_stats.down_packets, int(stream_stats.bytes/stream_stats.packet_count),
                              average_bytes_up, average_bytes_down,stream_stats.bytes, stream_stats.set_duration(),
                              stream_stats.set_ecart_type(), stream_stats.set_inter_packet_time_mean_up(),stream_stats.set_inter_packet_time_mean_down(),
                              stream_stats.set_inter_packet_time_ecart_type_up(),stream_stats.set_inter_packet_time_ecart_type_down()])

    try:
        with open(output_key,'w',newline='') as key_file:
            writer = csv.writer(key_file)
            writer.writerow(["Stream ID"])
            for stream_id, stream_stats in stats.items():
                if stream_stats.packet_count >= 10:
                    Hash_ID=hashlib.sha256(f"{stream_id}-{stream_stats.transport_protocol}".encode()).hexdigest()
                    writer.writerow([Hash_ID])
    except FileNotFoundError:
        # Si le fichier n'existe pas, on le crée dans le fichier
        os.makedirs(os.path.dirname(output_key), exist_ok=True)
        with open(output_key,'w',newline='') as key_file:
            writer = csv.writer(key_file)
            writer.writerow(["Stream ID"])
            for stream_id, stream_stats in stats.items():
                if stream_stats.packet_count >= 10:
                    Hash_ID=hashlib.sha256(f"{stream_id}-{stream_stats.transport_protocol}".encode()).hexdigest()
                    writer.writerow([Hash_ID])


debut = time.time()

pathname = sys.argv[1]
#le nom du fichier de sortie csv et le meme que le fichier pcap d'entré

csv_file = os.path.join("csv", os.path.basename(pathname)[:-7] + '.csv')
key_file = os.path.join("key", os.path.basename(pathname)[:-7] +"-clé"+ '.csv')
print(csv_file)
print(key_file)

stream_stats = analyze_pcap_file(pathname)
write_csv(stream_stats, csv_file,key_file)


fin= time.time()
print("temps  : ", fin - debut," secondes")