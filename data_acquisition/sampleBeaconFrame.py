import sys
import argparse
from netaddr import EUI
import pyshark

EXPECTED_BEACON_INTERVAL = 102400 #microseconds

def process_data_pcap(capture, outfile):
    prev_seq_number = 0 
    prev_beacon_timestamp = 0
    timestamp_deviation = 0

    #header
    outfile.write(f"beacon_interval (us)\n")
    for pkt in capture:
        #Retrieve Data
        seq_num = int(pkt.wlan.seq)
        beacon_timestamp = int(pkt["wlan.mgt"].wlan_fixed_timestamp)
        #Process Data
        seq_num_diff = seq_num - prev_seq_number 
        beacon_interval = beacon_timestamp - prev_beacon_timestamp
        timestamp_deviation = EXPECTED_BEACON_INTERVAL - beacon_interval

        if seq_num_diff == 1:
            outfile.write(f"{beacon_interval}\n")
        
        prev_seq_number = seq_num
        prev_beacon_timestamp = beacon_timestamp

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?',required=True, help='input file')
    parser.add_argument('-o', '--output', nargs='?',required=False, help='output file')
    parser.add_argument('-a', '--access_point_mac', nargs='?',required=True, help='access point mac')
    
    args=parser.parse_args()
    
    try:
        ap_mac=EUI(args.access_point_mac)
    except:
        print('{} is not a MAC address'.format(args.access_point_mac))
        sys.exit()
    
    fileInput=args.input
    
    if args.output is None:
        tmp=str.split(fileInput, ".")[0]
        fileOutput=tmp+".csv"
    else:
        fileOutput=args.output
        
    outfile = open(fileOutput,'w') 
    
    #beacon frame and access point mac address
    filter = f"(wlan.fc.type_subtype == 8) && (wlan.ta == {ap_mac})"
    
    capture = pyshark.FileCapture(fileInput, display_filter=filter)
    with open(fileOutput,'w') as outfile:
        process_data_pcap(capture, outfile)

if __name__ == '__main__':
    main()
