import sys
import argparse
from netaddr import EUI
import pyshark
import logging, sys



ASSOCIATION_REQUEST_SUBTYPE = 0
ASSOCIATION_RESPONSE_SUBTYPE = 1
AUTHENTICATIONS_SUBTYPE = 11

#Transation sequence:
#   Authentication request     (client -> AP)
#   Authentication response    (AP -> client)
#   Association request        (client -> AP)
#   Association response       (AP -> client)
#   EAPOL (Message 1)          (AP -> client)
#   EAPOL (Message 2)          (client -> AP)
#   EAPOL (Message 3)          (AP -> client)
#   EAPOL (Message 4)          (client -> AP)
is_authentication_request = lambda pkt, ap_mac : hasattr(pkt, "wlan") and int(pkt.wlan.fc_type_subtype, base=16) == AUTHENTICATIONS_SUBTYPE and EUI(pkt.wlan.ra) == ap_mac
is_authentication_response = lambda pkt, ap_mac : hasattr(pkt, "wlan") and int(pkt.wlan.fc_type_subtype, base=16) == AUTHENTICATIONS_SUBTYPE and EUI(pkt.wlan.ta) == ap_mac

is_association_request = lambda pkt, ap_mac : hasattr(pkt, "wlan") and int(pkt.wlan.fc_type_subtype, base=16) == ASSOCIATION_REQUEST_SUBTYPE and EUI(pkt.wlan.ra) == ap_mac
is_association_response = lambda pkt, ap_mac : hasattr(pkt, "wlan") and int(pkt.wlan.fc_type_subtype, base=16) == ASSOCIATION_RESPONSE_SUBTYPE and EUI(pkt.wlan.ta) == ap_mac

is_eapol_msg_1 = lambda pkt, ap_mac : hasattr(pkt, "wlan") and hasattr(pkt, "eapol") and int(pkt.eapol.wlan_rsna_keydes_msgnr) == 1 and EUI(pkt.wlan.ta) == ap_mac
is_eapol_msg_2 = lambda pkt, ap_mac : hasattr(pkt, "wlan") and hasattr(pkt, "eapol") and int(pkt.eapol.wlan_rsna_keydes_msgnr) == 2 and EUI(pkt.wlan.ra) == ap_mac
is_eapol_msg_3 = lambda pkt, ap_mac : hasattr(pkt, "wlan") and hasattr(pkt, "eapol") and int(pkt.eapol.wlan_rsna_keydes_msgnr) == 3 and EUI(pkt.wlan.ta) == ap_mac
is_eapol_msg_4 = lambda pkt, ap_mac : hasattr(pkt, "wlan") and hasattr(pkt, "eapol") and int(pkt.eapol.wlan_rsna_keydes_msgnr) == 4 and EUI(pkt.wlan.ra) == ap_mac


def skip_duplicate_pkt(capture_iter, condition, ap_mac):
    pkt = next(capture_iter)
    while(condition(pkt, ap_mac)):
        logging.debug(f"Duplicate frame detected! No. {pkt.number}")
        pkt = next(capture_iter)
    
    return pkt

def process_next_transaction(capture_iter, ap_mac, outfile):
    global num_complete_transaction
    global num_skipped_transaction

    timestamp_authentication_request = 0
    timestamp_authentication_response = 0
    time_interval_authentication = 0

    timestamp_association_request = 0
    timestamp_association_response= 0
    time_interval_association = 0

    timestamp_eapol_message_1= 0
    timestamp_eapol_message_2= 0
    time_interval_eapol_first = 0

    timestamp_eapol_message_3= 0
    timestamp_eapol_message_4= 0
    time_interval_eapol_second = 0

    #---------------------------------------------------
    #------Authentication request (client -> AP)--------
    #---------------------------------------------------
    pkt = next(capture_iter) 
    while(not is_authentication_request(pkt, ap_mac)): # Find authentication request
        pkt = next(capture_iter) 

    logging.debug(f"Authentication request (client -> AP). No. {pkt.number}")
    timestamp_authentication_request = float(pkt.sniff_timestamp)

    pkt = skip_duplicate_pkt(capture_iter, is_authentication_request, ap_mac)

    #----------------------------------------------------
    #------Authentication response (AP -> client)--------
    #----------------------------------------------------
    if(not is_authentication_response(pkt, ap_mac)):
        logging.debug(f"Missing authentication response. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    logging.debug(f"Authentication response (AP -> client). No. {pkt.number}")
    timestamp_authentication_response = float(pkt.sniff_timestamp)

    time_interval_authentication = (timestamp_authentication_response - timestamp_authentication_request) * 10e+6 #us

    pkt = skip_duplicate_pkt(capture_iter, is_authentication_response, ap_mac)

    #---------------------------------------------------
    #--------Association request (client -> AP)---------
    #---------------------------------------------------
    if(not is_association_request(pkt, ap_mac)):
        logging.debug(f"Missing association request. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"Association request (AP -> client). No. {pkt.number}")
    timestamp_association_request = float(pkt.sniff_timestamp)

    pkt = skip_duplicate_pkt(capture_iter, is_association_request, ap_mac)

    #---------------------------------------------------
    #--------Association reponse (client -> AP)---------
    #---------------------------------------------------
    if(not is_association_response(pkt, ap_mac)):
        logging.debug(f"Missing association response. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"Association response (AP -> client). No. {pkt.number}")
    timestamp_association_response = float(pkt.sniff_timestamp)

    time_interval_association = (timestamp_association_response - timestamp_association_request) * 10e+6 #us

    pkt = skip_duplicate_pkt(capture_iter, is_association_response, ap_mac)
    
    #---------------------------------------------------
    #--------EAPOL (Message 1) (AP -> client)-----------
    #---------------------------------------------------
    if(not is_eapol_msg_1(pkt, ap_mac)):
        logging.debug(f"Missing eapol message 1. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"EAPOL (Message 1) (AP -> client). No. {pkt.number}")
    timestamp_eapol_message_1 = float(pkt.sniff_timestamp)

    pkt = skip_duplicate_pkt(capture_iter, is_eapol_msg_1, ap_mac)

    #---------------------------------------------------
    #--------EAPOL (Message 2) (client -> AP)-----------
    #---------------------------------------------------
    if(not is_eapol_msg_2(pkt, ap_mac)):
        logging.debug(f"Missing eapol message 2. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"EAPOL (Message 2) (client -> AP). No. {pkt.number}")
    timestamp_eapol_message_2 = float(pkt.sniff_timestamp)

    time_interval_eapol_first = (timestamp_eapol_message_2 - timestamp_eapol_message_1) * 10e+6 #us
    pkt = skip_duplicate_pkt(capture_iter, is_eapol_msg_1, ap_mac)

    #---------------------------------------------------
    #--------EAPOL (Message 3) (AP -> client)-----------
    #---------------------------------------------------
    if(not is_eapol_msg_3(pkt, ap_mac)):
        logging.debug(f"Missing eapol message 3. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"EAPOL (Message 3) (AP -> client). No. {pkt.number}")
    timestamp_eapol_message_3 = float(pkt.sniff_timestamp)

    pkt = skip_duplicate_pkt(capture_iter, is_eapol_msg_3, ap_mac)

    #---------------------------------------------------
    #--------EAPOL (Message 4) (client -> AP)-----------
    #---------------------------------------------------
    if(not is_eapol_msg_4(pkt, ap_mac)):
        logging.debug(f"Missing eapol message 4. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"EAPOL (Message 4) (client -> AP). No. {pkt.number}")
    timestamp_eapol_message_4 = float(pkt.sniff_timestamp)

    time_interval_eapol_second = (timestamp_eapol_message_4 - timestamp_eapol_message_3) * 10e+6 #us

    num_complete_transaction += 1
    total_transaction = num_complete_transaction + num_skipped_transaction
    logging.debug(f"----------------Transaction Complete {total_transaction}----------------\n")
    outfile.write(f"{time_interval_authentication},{time_interval_association},{time_interval_eapol_first},{time_interval_eapol_second}\n")

def process_data_pcap(capture, ap_mac, outfile):
    global num_complete_transaction
    global num_skipped_transaction
    num_complete_transaction = 0
    num_skipped_transaction = 0

    count = 0

    #header
    outfile.write("time_interval_authentication,time_interval_association,time_interval_eapol_first,time_interval_eapol_second\n"),
    capture_iter = iter(capture)
    
    while(True):
        try:
            process_next_transaction(capture_iter, ap_mac, outfile)
        except StopIteration:
            break
    
    print(f"Number of complete transactions: {num_complete_transaction}")
    print(f"Number of skipped transactions: {num_skipped_transaction}")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?',required=True, help='input file')
    parser.add_argument('-o', '--output', nargs='?',required=False, help='output file')
    parser.add_argument('-a', '--access_point_mac', nargs='?',required=True, help='access point mac')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

    args=parser.parse_args()
    
    if(args.verbose):
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    
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
    
    # (association request || association reponse || authentications || authentication eapol) 
    # && 
    # (AP address (transmission) || AP address (receiver) )
    filter = f"""
    (wlan.fc.type_subtype == {ASSOCIATION_REQUEST_SUBTYPE} ||  wlan.fc.type_subtype == {ASSOCIATION_RESPONSE_SUBTYPE} 
    || wlan.fc.type_subtype == {AUTHENTICATIONS_SUBTYPE} || eapol.keydes.type == 2) 
    && 
    (wlan.ta == {ap_mac} || wlan.ra == {ap_mac})
    """
    
    capture = pyshark.FileCapture(fileInput, display_filter=filter)
    with open(fileOutput,'w') as outfile:
        process_data_pcap(capture, ap_mac, outfile)

if __name__ == '__main__':
    main()
