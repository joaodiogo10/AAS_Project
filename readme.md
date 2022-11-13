# Packet Capture

## Setup interface

```console
sudo ifconfig wlx00c0ca53a4b4 down
sudo iwconfig wlx00c0ca53a4b4 mode monitor
sudo ifconfig wlx00c0ca53a4b4 up
sudo iwconfig wlx00c0ca53a4b4 channel 6

sudo iw dev
```
## Wireshark filters

### Frame type

- wlan.fc.type_subtype == 0	    | association request
- wlan.fc.type_subtype == 1	    | association response
- wlan.fc.type_subtype == 2	    | re-association request
- wlan.fc.type_subtype == 3	    | re-association response
- wlan.fc.type_subtype == 4	    | probe requests
- wlan.fc.type_subtype == 5	    | probe responses
- wlan.fc.type_subtype == 8	    | beacons
- wlan.fc.type_subtype == 10	| disassosiations
- wlan.fc.type_subtype == 11	| authentications
- wlan.fc.type_subtype == 12	| deauthentications

### Authentication eapol
- eapol.keydes.type == 2		| authentication eapol 

### Access point comunications filter
- wlan.ta == <access_point_mac>    | transmission address
- wlan.ra == <access_point_mac>   | receiver address


### Examples

- (association request || association reponse || authentications || authentication eapol) && (AP address (transmission) || AP address (receiver) )

```console
(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || wlan.fc.type_subtype == 11 || eapol.keydes.type == 2) && (wlan.ta == 84:0b:7c:b6:87:26 || wlan.ra == 84:0b:7c:b6:87:26)
```

- (beacons) && (AP address (transmission))

```console
(wlan.fc.type_subtype == 8) && (wlan.ta == 84:0b:7c:b6:87:26)
```

# Python code

## Virtual environment

```console
python3 -m venv -venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Beacon frame

### Data sampling
#### Usage

python processBeaconFrame.py -i <input_file> -a <access_point_mac>

Example:
```console
python3 processBeaconFrame.py -i packets/homeBeacon2.pcapng -a 84:0b:7c:b6:87:26
```

### Plot data

#### Usage

python3 plotBeaconFrame.py -i <input_file> [-o <output_file>]

Use the output file from the previous step.

Plot example:

![beacon plot example](images/beaconPlot.png)
## Authentication transaction
### Data sampling
#### Usage

python3 processAuthentication.py -i <input_file> -a <access_point_mac> [-v]

Example:
```console
python3 processAuthentication.py -i packets/homeAuthentication.pcapng -a 84:0b:7c:b6:87:26 -v 
```

