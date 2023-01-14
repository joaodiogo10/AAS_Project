import sys
import argparse
from netaddr import EUI
import pyshark
import logging, sys

ASSOCIATION_REQUEST_SUBTYPE = 0
ASSOCIATION_RESPONSE_SUBTYPE = 1
AUTHENTICATIONS_SUBTYPE = 11

# Measurements:
#   Time between Authentication request - Authentication response
#   Time between Association request - Association response
#   Time between Association response - EAPOL (Message 1)
#   Time between EAPOL (Message 2) - EAPOL (Message 3)

# Transation sequence:
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

def process_next_transaction(capture_iter, ap_macs, outfile, eapol=True):
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
    access_point_mac = EUI(pkt.wlan.ra)
    while(not is_authentication_request(pkt, access_point_mac)): # Find authentication request
        pkt = next(capture_iter) 
        access_point_mac = EUI(pkt.wlan.ra)

    logging.debug(f"Authentication request (client -> AP). No. {pkt.number}")
    timestamp_authentication_request = float(pkt.sniff_timestamp)

    pkt = skip_duplicate_pkt(capture_iter, is_authentication_request, access_point_mac)

    #----------------------------------------------------
    #------Authentication response (AP -> client)--------
    #----------------------------------------------------
    if(not is_authentication_response(pkt, access_point_mac)):
        logging.debug(f"Missing authentication response. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    logging.debug(f"Authentication response (AP -> client). No. {pkt.number}")
    timestamp_authentication_response = float(pkt.sniff_timestamp)

    time_interval_authentication = (timestamp_authentication_response - timestamp_authentication_request) * 10e+6 #us

    pkt = skip_duplicate_pkt(capture_iter, is_authentication_response, access_point_mac)

    #---------------------------------------------------
    #--------Association request (client -> AP)---------
    #---------------------------------------------------
    if(not is_association_request(pkt, access_point_mac)):
        logging.debug(f"Missing association request. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"Association request (AP -> client). No. {pkt.number}")
    timestamp_association_request = float(pkt.sniff_timestamp)

    pkt = skip_duplicate_pkt(capture_iter, is_association_request, access_point_mac)

    #---------------------------------------------------
    #--------Association reponse (client -> AP)---------
    #---------------------------------------------------
    if(not is_association_response(pkt, access_point_mac)):
        logging.debug(f"Missing association response. No. {pkt.number}")
        logging.debug(f"----------------Transaction Skipped----------------\n")
        num_skipped_transaction += 1
        return
    
    logging.debug(f"Association response (AP -> client). No. {pkt.number}")
    timestamp_association_response = float(pkt.sniff_timestamp)

    time_interval_association = (timestamp_association_response - timestamp_association_request) * 10e+6 #us

    pkt = skip_duplicate_pkt(capture_iter, is_association_response, access_point_mac)
    
    if eapol:
        #---------------------------------------------------
        #--------EAPOL (Message 1) (AP -> client)-----------
        #---------------------------------------------------
        if(not is_eapol_msg_1(pkt, access_point_mac)):
            logging.debug(f"Missing eapol message 1. No. {pkt.number}")
            logging.debug(f"----------------Transaction Skipped----------------\n")
            num_skipped_transaction += 1
            return
        
        logging.debug(f"EAPOL (Message 1) (AP -> client). No. {pkt.number}")
        timestamp_eapol_message_1 = float(pkt.sniff_timestamp)

        time_interval_eapol_first = (timestamp_eapol_message_1 - timestamp_association_response) * 10e+6 #us

        pkt = skip_duplicate_pkt(capture_iter, is_eapol_msg_1, access_point_mac)

        #---------------------------------------------------
        #--------EAPOL (Message 2) (client -> AP)-----------
        #---------------------------------------------------
        if(not is_eapol_msg_2(pkt, access_point_mac)):
            logging.debug(f"Missing eapol message 2. No. {pkt.number}")
            logging.debug(f"----------------Transaction Skipped----------------\n")
            num_skipped_transaction += 1
            return
        
        logging.debug(f"EAPOL (Message 2) (client -> AP). No. {pkt.number}")
        timestamp_eapol_message_2 = float(pkt.sniff_timestamp)

        pkt = skip_duplicate_pkt(capture_iter, is_eapol_msg_2, access_point_mac)

        #---------------------------------------------------
        #--------EAPOL (Message 3) (AP -> client)-----------
        #---------------------------------------------------
        if(not is_eapol_msg_3(pkt, access_point_mac)):
            logging.debug(f"Missing eapol message 3. No. {pkt.number}")
            logging.debug(f"----------------Transaction Skipped----------------\n")
            num_skipped_transaction += 1
            return
        
        logging.debug(f"EAPOL (Message 3) (AP -> client). No. {pkt.number}")
        timestamp_eapol_message_3 = float(pkt.sniff_timestamp)
        
        time_interval_eapol_second = (timestamp_eapol_message_3 - timestamp_eapol_message_2) * 10e+6 #us

        pkt = skip_duplicate_pkt(capture_iter, is_eapol_msg_3, access_point_mac)

    #Ignore last transaction packet
    #---------------------------------------------------
    #--------EAPOL (Message 4) (client -> AP)-----------
    #---------------------------------------------------
    # if(not is_eapol_msg_4(pkt, ap_mac)):
    #     logging.debug(f"Missing eapol message 4. No. {pkt.number}")
    #     logging.debug(f"----------------Transaction Skipped----------------\n")
    #     num_skipped_transaction += 1
    #     return
    
    # logging.debug(f"EAPOL (Message 4) (client -> AP). No. {pkt.number}")
    # timestamp_eapol_message_4 = float(pkt.sniff_timestamp)


    num_complete_transaction += 1
    total_transaction = num_complete_transaction + num_skipped_transaction
    logging.debug(f"----------------Transaction Complete {total_transaction}----------------\n")
    outfile.write(f"{time_interval_authentication},{time_interval_association},{time_interval_eapol_first},{time_interval_eapol_second}\n")

def process_data_pcap(capture, ap_macs, outfile):
    global num_complete_transaction
    global num_skipped_transaction
    num_complete_transaction = 0
    num_skipped_transaction = 0

    count = 0

    #header
    outfile.write("time_interval_authentication (us),time_interval_association (us),time_interval_eapol_first (us),time_interval_eapol_second (us)\n"),
    capture_iter = iter(capture)
    
    while(True):
        try:
            process_next_transaction(capture_iter, ap_macs, outfile, eapol=True)
        except StopIteration:
            break
    
    print(f"Number of complete transactions: {num_complete_transaction}")
    print(f"Number of skipped transactions: {num_skipped_transaction}")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?',required=True, help='input file')
    parser.add_argument('-o', '--output', nargs='?',required=False, help='output file')
    parser.add_argument('-a', '--access_point_mac', nargs='+',required=True, help='access point mac(s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

    args=parser.parse_args()
    
    if(args.verbose):
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    
    try:
        ap_macs = []
        for mac in args.access_point_mac:
            ap_macs.append(EUI(mac))
    except:
        print('{} is not a MAC address'.format(mac))
        sys.exit()
    
    fileInput=args.input
    
    if args.output is None:
        tmp=str.split(fileInput, ".")[0]
        fileOutput=tmp+".csv"
    else:
        fileOutput=args.output
        
    outfile = open(fileOutput,'w') 

    filter_access_points = "(" + " || ".join(f"(wlan.ta == {mac} || wlan.ra == {mac})" for mac in ap_macs) + ")"
    print(filter_access_points)
    # (association request || association reponse || authentications || authentication eapol) 
    # && 
    # (AP address (transmission) || AP address (receiver) )
    filter = f"""
    (wlan.fc.type_subtype == {ASSOCIATION_REQUEST_SUBTYPE} ||  wlan.fc.type_subtype == {ASSOCIATION_RESPONSE_SUBTYPE} 
    || wlan.fc.type_subtype == {AUTHENTICATIONS_SUBTYPE} || eapol.keydes.type == 2) 
    && 
    {filter_access_points}
    """
    
    capture = pyshark.FileCapture(fileInput, display_filter=filter)
    with open(fileOutput,'w') as outfile:
        process_data_pcap(capture, ap_macs, outfile)

if __name__ == '__main__':
    main()
