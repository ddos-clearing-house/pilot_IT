# pilot_IT
DDoS Clearing House Pilot Italy

**misp_exporter.py** : 
exports a fingerprint json file to a MISP event and publish it on a MISP instance of your choice, the default MISP instance is misp.concordia-h2020.eu

**Usage** :

  --version : prints version and exits

  -v or --verbose : prints information messages
  
  -d or --debug : prints debug information
  
  -f or --fingerprint : fingerprint json file
  
  -n or --node : the json fingerprint file node, default value is "attackers"
  
  -u or --misp_url : URL of the MISP instance where to publish the event, default value is misp.concordia-h2020.eu
  
  -k or --misp_apikey : API key of the account on the MISP instance where to publish
  
  -l or --distribution, type=int : The distribution level for the newly created event [0-3]
  
  -i or --event_info : The event info field, i.e., the event name in MISP
  
  -a or --analysis_level, type=int : The analysis level of the newly created event [0-2]
  
  -t or --threat_level, type=int : The threat level ID of the newly created event [1-4]
  
  -s or --subnets : add subnets as attributes instead of ips


**Requirements** : 

Install PyMISP from pip

pip install pymisp

or

pip3 install pymisp

