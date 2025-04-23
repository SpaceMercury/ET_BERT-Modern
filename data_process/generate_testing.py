#!/usr/bin/python3
#-*- coding:utf-8 -*-

import numpy as np
import argparse
import os
import sys
import csv
import dpkt
import binascii
import scapy.all as scapy
import random
import shutil
from tqdm import tqdm
import subprocess
from flowcontainer.extractor import extract
from collections import defaultdict

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)


def extract_flows(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    flows = defaultdict(list)

    for pkt in packets:
        if scapy.IP in pkt and (scapy.TCP in pkt or scapy.UDP in pkt):
            proto = 'TCP' if scapy.TCP in pkt else 'UDP'
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            sport = pkt[proto].sport
            dport = pkt[proto].dport

            flow_key = (src, dst, sport, dport, proto)
            flows[flow_key].append(pkt)

    return flows


def get_feature_flow(label_pcap, payload_len, payload_pac):
    feature_data = []
    try:
        
        flows = extract_flows(label_pcap)
        # Extract flows from packets
        for flow_id, pkts in flows.items():
            packet_count = 0  
            flow_data_string = '' 
            
            for packet in pkts:
                packet_count += 1
                if packet_count == payload_pac:
                    packet_data = packet.copy()
                    data = (binascii.hexlify(bytes(packet_data)))
                    packet_string = data.decode()[76:]  
                    flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag=True)
                    break
                else:
                    packet_data = packet.copy()
                    data = (binascii.hexlify(bytes(packet_data)))
                    packet_string = data.decode()[76:]  # Limit string length
                    flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag=True)
                    
            feature_data.append(flow_data_string)
        return feature_data
    except Exception as e:
        print(f"Error in get_feature_flow: {e}")
        return -1


def get_feature_packet(label_pcap, payload_len, max_pkt_total=5000, remove_header=False):
    feature_data = []
    max_pkts = 0
    packets = scapy.rdpcap(label_pcap)
    
    for packet in packets:

        if not (scapy.IP in packet and (scapy.TCP in packet or scapy.UDP in packet)):
            continue


        #is packet tcp then it needs to be 0.14
        if scapy.TCP in packet:
            if (len(packet)/1024) < 0.14:
                continue
        elif scapy.UDP in packet:
            if (len(packet)/1024) < 0.1:
                continue


        #print(packet)
        if max_pkts >= max_pkt_total:
            break
        max_pkts += 1
        packet_data = packet.copy()
        data = binascii.hexlify(bytes(packet_data))
        packet_string = data.decode()

        
        if remove_header:
            if scapy.TCP in packet:
                # Access the payload directly after the TCP header (including options)
                payload_layer = packet[scapy.TCP].payload
                if payload_layer:
                    payload_bytes = bytes(payload_layer)
                    new_packet_string = binascii.hexlify(payload_bytes).decode()

            elif scapy.UDP in packet:
                 # Access the payload directly after the UDP header
                 payload_layer = packet[scapy.UDP].payload
                 if payload_layer:
                    payload_bytes = bytes(payload_layer)
                    new_packet_string = binascii.hexlify(payload_bytes).decode()

        else:
            new_packet_string = packet_string[76:]

        # Append each packet's bigram transformation as a separate payload
        payload_string = bigram_generation(new_packet_string, packet_len=payload_len, flag=True)
        feature_data.append(payload_string)
    
    return feature_data

def cut(obj, sec):
    """Cut string into sections of specific length"""
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    try:
        remanent_count = len(result[0])%4
    except Exception as e:
        remanent_count = 0
        print("cut datagram error!")
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

def bigram_generation(packet_datagram, packet_len=64, flag=True):
    """Generate bigrams from packet data"""
    result = ''
    generated_datagram = cut(packet_datagram,1)
    token_count = 0
    for sub_string_index in range(len(generated_datagram)):
        if sub_string_index != (len(generated_datagram) - 1):
            token_count += 1
            if token_count > packet_len:
                break
            else:
                merge_word_bigram = generated_datagram[sub_string_index] + generated_datagram[sub_string_index + 1]
        else:
            break
        result += merge_word_bigram
        result += ' '
    
    return result

def size_format(size):
    """Format file size in KB"""
    file_size = '%.3f' % float(size/1000)
    return file_size

def extract_all_pcaps(base_path, dataset_level='packet', payload_len=64, payload_pkts=5, max_packets_per_category=None, remove_header=False):
    """Iterate over all folders, collect all PCAP files, and process them with numeric labels."""
    payloads = []
    labels = []
    folder_to_label = {}  # Map folder names to numeric labels
    current_label = 0
    category_packet_count = defaultdict(int)  # Track packet count per category

    # Walk through all directories and subdirectories
    for root, dirs, files in os.walk(base_path):
        for file in tqdm(files):
            if file.endswith('.pcap') or file.endswith('.pcapng'):
                pcap_file = os.path.join(root, file)
                folder_name = os.path.basename(root)  # Get the folder name

                # Assign a numeric label to the folder if not already assigned
                if folder_name not in folder_to_label:
                    folder_to_label[folder_name] = current_label
                    current_label += 1

                numeric_label = folder_to_label[folder_name]

                # Skip processing if max packets per category is reached
                if max_packets_per_category and category_packet_count[folder_name] >= max_packets_per_category:
                    continue

                try:
                    if dataset_level == 'packet':
                        # Packet-level processing
                        result = get_feature_packet(pcap_file, payload_len, remove_header=remove_header)
                    elif dataset_level == 'flow':
                        # Flow-level processing
                        result = get_feature_flow(pcap_file, payload_len, payload_pkts)
                    else:
                        print(f"Invalid dataset_level: {dataset_level}")
                        continue

                    if result != -1:  # Check if valid result
                        # Limit the number of packets added for this category
                        remaining_packets = max_packets_per_category - category_packet_count[folder_name] if max_packets_per_category else len(result)
                        result = result[:remaining_packets]
                        payloads.extend(result)
                        labels.extend([numeric_label] * len(result))  # Assign the numeric label
                        category_packet_count[folder_name] += len(result)

                except Exception as e:
                    print(f"Error processing PCAP file {pcap_file}: {e}")
                    continue

    # Save the folder-to-label mapping to a file
    label_map_path = "label_map_file.txt"
    with open(label_map_path, 'w') as f:
        for folder, label in folder_to_label.items():
            f.write(f"{label} -> {folder}\n")
    print(f"Label mapping saved to {label_map_path}")

    return payloads, labels

def write_dataset_tsv(data, labels, file_dir, type_name):

    """Write data and labels to TSV file"""
    dataset_file = [["label", "text_a"]]
    for label, item in zip(labels, data):
        dataset_file.append([label, item])
    
    tsv_path = os.path.join(file_dir, f"{type_name}_dataset.tsv")
    with open(tsv_path, 'w', newline='') as f:
        tsv_w = csv.writer(f, delimiter='\t')
        tsv_w.writerows(dataset_file)
    
    print(f"Created {tsv_path}")
    return tsv_path

def generate_unlabeled(tsv_path):
    """Generate unlabeled version of the TSV"""
    nolabel_data = ""
    with open(tsv_path, newline='') as f:
        data = csv.reader(f, delimiter='\t')
        next(data)  # Skip header
        for row in data:
            if len(row) > 1:
                nolabel_data += row[1] + '\n'
    
    nolabel_path = tsv_path.replace("_dataset.tsv", "_nolabel_dataset.tsv")
    with open(nolabel_path, 'w', newline='') as f:
        f.write("text_a\n")  # Write header
        f.write(nolabel_data)
    
    print(f"Created unlabeled version: {nolabel_path}")
    return nolabel_path

def main():
    parser = argparse.ArgumentParser(description="Generate testing TSV from PCAP file with specified label")
    
    parser.add_argument("--pcap_path", type=str, required=False, help="Path to PCAP folder")
    parser.add_argument("--pcap_file", type=str, required=False, help="Path to PCAP file")
    parser.add_argument("--label", type=str, required=False, help="Label for the PCAP file")
    parser.add_argument("--output_dir", type=str, default="./", help="Directory to save TSV files")
    parser.add_argument("--type", type=str, default="test", help="Type of dataset (test, train, valid)")
    parser.add_argument("--max_packets", type=int, default=0, help="Maximum number of packets to process")
    parser.add_argument("--dataset_level", type=str, default="packet", choices=["packet", "flow"], 
                        help="Level of analysis (packet or flow)")
    parser.add_argument("--payload_length", type=int, default=64, help="Maximum length of payload to extract")
    parser.add_argument("--training", action='store_true', help="Flag to indicate if training, validation, and test split is needed")
    parser.add_argument("--remove-header", action='store_true', help="will cut the headers of the packets")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)


    if args.training:

        if args.dataset_level == "packet":
            print(f"Extracting payloads from {args.pcap_path}...")
            payloads, labels = extract_all_pcaps(args.pcap_path, dataset_level='packet', payload_len=args.payload_length, max_packets_per_category=args.max_packets, remove_header=args.remove_header)
        elif args.dataset_level == "flow":
            print(f"Extracting payloads from {args.pcap_path}...")
            payloads, labels = extract_all_pcaps(args.pcap_path, dataset_level='flow', payload_len=args.payload_length, payload_pkts=5, max_packets_per_category=args.max_packets, remove_header=args.remove_header)


        print(f"Extracted {len(payloads)} payloads")

        if not payloads:
            print("No payloads found in PCAP!")
            return


        print("Performing training, validation, and test split...")
        combined = list(zip(payloads, labels))
        random.shuffle(combined)
        payloads, labels = zip(*combined)

        total = len(payloads)
        train_end = int(0.8 * total)
        valid_end = int(0.9 * total)

        train_payloads = payloads[:train_end]
        train_labels = labels[:train_end]
        valid_payloads = payloads[train_end:valid_end]
        valid_labels = labels[train_end:valid_end]
        test_payloads = payloads[valid_end:]
        test_labels = labels[valid_end:]

        train_tsv = write_dataset_tsv(train_payloads, train_labels, args.output_dir, "train")
        valid_tsv = write_dataset_tsv(valid_payloads, valid_labels, args.output_dir, "valid")
        test_tsv = write_dataset_tsv(test_payloads, test_labels, args.output_dir, "test")

        print(f"Generated training TSV file: {train_tsv}")
        print(f"Generated validation TSV file: {valid_tsv}")
        print(f"Generated test TSV file: {test_tsv}")

        generate_unlabeled(test_tsv)
    else:

        # If not training, just generate the TSV for the provided PCAP
        print(f"Generating TSV for {args.pcap_file}...")
        if args.pcap_file:
            # Use the provided label if specified
            if args.label:
                numeric_label = args.label
                payloads = get_feature_packet(args.pcap_file, payload_len=args.payload_length, remove_header=args.remove_header)
                labels = [numeric_label] * len(payloads)  # Assign the same label to all payloads
        else:
            return
        
        # Generate TSV with labels
        dataset_file = [["label", "text_a"]]
        for payload, label in zip(payloads, labels):
            dataset_file.append([label, payload])

        tsv_path = os.path.join(args.output_dir, f"predict_{args.type}_dataset.tsv")
        with open(tsv_path, 'w', newline='') as f:
            tsv_w = csv.writer(f, delimiter='\t')
            tsv_w.writerows(dataset_file)

        # Generate unlabeled version
        generate_unlabeled(tsv_path)
    
if __name__ == "__main__":
    main()