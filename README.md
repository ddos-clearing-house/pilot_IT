# pilot_IT
**DDoS Clearing House Pilot Italy**

**misp_exporter.py** : 
converts a fingerprint json file to a MISP event and publish it on a MISP instance. It also downloads in the local directory a file containig the snort rules created from the MISP event. The MISP instance URL and automation key can be filled in directly in pymisp or as a cmd line argument or in the misp_exporter.py file. 

**Usage**

  --version : prints version and exits

  -v or --verbose : prints information messages
  
  -d or --debug : prints debug information
  
  -f or --fingerprint : name of the fingerprint json file
  
  -n or --node : the json fingerprint file node, default value is "attackers"
  
  -u or --misp_url : URL of the MISP instance where to publish the event
  
  -k or --misp_apikey : MISP automation key of the account on the MISP instance where the event should be published
  
  -l or --distribution, type=int : The distribution level for the newly created event [0-3]
  
  -i or --event_info : The event info field, i.e., the event name in MISP
  
  -a or --analysis_level, type=int : The analysis level of the newly created event [0-2]
  
  -t or --threat_level, type=int : The threat level ID of the newly created event [1-4]
  
  -s or --subnets : add subnets as attributes of the event instead of ips (reccomended if the number of ip addresses is huge)


**Requirements** 

The following modules should be installed:

pymisp: *pip install pymisp* or *pip3 install pymisp*

requests

ipaddr, ipaddress

pandas

json


