**Theodore Wagner**  
**it610_ids**  
IT610 project repository for a network intrusion detection system  

## ids.py functions
### main
- opens the connection on interface and captures packets on that interface
- calls `parse_packet` function to parse the packet
- calls `db_action` to perform database functions with parsed data

### eth_addr
- converts input data to human readable Ethernet format (i.e. ff:ff:ff:ff:ff:ff:ff)

### parse_packet
- parses from packet:
- source MAC Address
- source IP Address
- source and destination port (TCP and UDP packets only)
- payload data

### db_action
- checks database for any previous records with that IP address, then for any previous records with that MAC address
- if none found, calls `log_info` to log the information as _New Source Host_
- checks database for any previous records with that IP address and MAC address and like payload data
- if none found, calls `log_info` to log the information as _Atypical Data Received_
- regardless of above, logs the collection of information parsed from `parse_packet` into the database

### log_info
- logs the corresponding warning message from the call in `db_action`, the source IP address, and the source MAC address
- prints out a message to the user to check the log, followed by the path to the log file
