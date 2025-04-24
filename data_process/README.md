## Overview

The `generate_testing.py` script is a preprocessing tool that converts network packet captures (PCAP files) into text-based datasets suitable for training and evaluating machine learning models, particularly for the ET-BERT project. It extracts payload data from network traffic and transforms it into a format compatible with BERT-style transformer models.

## Key Features
Processes both individual PCAP files and directories containing multiple PCAPs

Supports both packet-level and flow-level analysis

Automatically assigns numeric labels based on folder structure

Creates TSV files with labeled data for training, validation, and testing

Generates unlabeled datasets for inference


## Core Functionality

Data Extraction Methods

1. Packet-Level Processing: Extracts individual packets and processes them independently
- Function: `get_feature_packet()`
- Each packet becomes a separate data point
2. Flow-Level Processing: Groups packets into flows based on the 5-tuple (source IP, destination IP, source port, destination port, protocol)
- Function: `get_feature_flow()`
- Multiple packets from the same flow are combined


### Data Transformation
The script transforms raw binary packet data into a text format through:

1. Hexlification: Converts binary data to hexadecimal representation
2. Payload Extraction: Removes packet headers
    - First 76 hex characters like in the paper
    - or if you use the --no-header option to just fully remove the headers
3. Bigram Generation: Creates bigrams (pairs of adjacent hex characters)
    - Function: bigram_generation()
    - Example: "abcdef" becomes "abbc bccd cdde deef"


### Dataset Creation
The script can:

1. Create datasets from existing categorized directories (training mode)
2. Process a single PCAP file with a specified label (testing mode)

## Usage
Command Line Arguments

```
python generate_testing.py [options]
```


Options:

- `--pcap_path`: Path to folder containing organized PCAP files

- `--pcap_file`: Path to an individual PCAP file

- `--label`: Label for a single PCAP file

- `--output_dir`: Directory to save TSV files (default: current directory)

- `--type`: Dataset type (test, train, valid) (default: test)

- `--max_packets`: Maximum packets to process per category (default: 0 = unlimited)

- `--dataset_level`: Level of analysis - packet or flow (default: packet)

- `--payload_length`: Maximum length of payload to extract (default: 64)

- `--training`: Flag to enable training mode, you have to give a folder instead of a file

- `--no-header` : No header flag will process the packets completely removing the Eth, IP, TCP headers (unlike original paper)



Example Usage:

Process a single PCAP file:
```
python generate_testing.py --pcap_file path/to/capture.pcap --label 0 --type test
```
Process multiple PCAPSs for training:
```
python generate_testing.py --pcap_path path/to/pcap/directory --training --dataset_level packet --payload_length 128 --output_dir ./output
```

Output Files
The script produces:

Labeled TSV Files: Format <type>_dataset.tsv with "label" and "text_a" columns
Unlabeled TSV Files: Format <type>_nolabel_dataset.tsv with only "text_a" column
Label Mapping File: label_map_file.txt showing the correspondence between numeric labels and folder names
