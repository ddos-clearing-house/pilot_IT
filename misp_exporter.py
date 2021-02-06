#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###############################################################################
#  
#  
# @copyright - mada - madi.skype@gmail.com 
# @copyright - Joao Ceron - ceron@botlog.org 
#  
###############################################################################

###############################################################################
### Python modules
import argparse
import logging
import os
import pandas as pd
import Trues

import signal
import sys
import string
import ipaddress
import json
import ipaddr
import math
import requests
import mmap
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPObject
from pymisp.tools import GenericObjectGenerator
#from keys import misp_url, misp_key, misp_verifycert
from pathlib import Path



# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass

###############################################################################
### Program settings

#default values, we use them if no cmd line arguments are present
#the fingerprint json file should always be present as an arg 
jfile = 'fingerprint.json'
node = 'attackers'
nodeamp = 'amplifiers'
reduced_item = {}
distribution = '1'
threat_level = '2'
event_info = 'Test DDoS event'
analysis_level = '2'
addips = True
nodedport = 'dstport'
nodeproto4 = 'ip_proto'
nodeproto7 = 'highest_protocol'
no_of_ips = 0
dstpot = 53
amp = False
att = False

#parameters fo concordia-2020
misp_url = 'https://misp.url/'
misp_key = 'misp automation key'
misp_verifycert = True

verbose = False
version = 0.1
program_name = os.path.basename(__file__)

    
#------------------------------------------------------------------------------
def parser_args ():

    parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]')
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-v","--verbose", help="print info msg", action="store_true")
    parser.add_argument("-d","--debug", help="print debug info", action="store_true")
    parser.add_argument("-f","--fingerprint", required=True, help="fingerprint json file")
    parser.add_argument("-n","--node", help="json file node, default attackers", action="store_true")
    parser.add_argument("-u","--misp_url", help="URL of the MISP instance where to publish", action="store_true")
    parser.add_argument("-k","--misp_apikey", help="API key of the user of the MISP instance where to publish", action="store_true")
    parser.add_argument("-l","--distribution", type=int, help="The distribution level setting used for the attributes and for the newly created event, if relevant. [0-3].")
    parser.add_argument("-i","--event_info", help="Used to populate the event info field, which is the event name in MISP")
    parser.add_argument("-a","--analysis_level", type=int, help="The analysis level of the newly created event, if applicable. [0-2]")
    parser.add_argument("-t","--threat_level", type=int, help="The threat level ID of the newly created event, if applicable. [1-4]")
    parser.add_argument("-s","--subnets", help="add subnets as attributes instead of ips", action="store_true")

    return parser

#------------------------------------------------------------------------------
def signal_handler(sig, frame):
    print('Ctrl+C detected.')
    sys.exit(0)
    
#------------------------------------------------------------------------------
def find_ips(args, node):

    file = args.fingerprint
    if (args.fingerprint):
        file = args.fingerprint
        if not (os.path.isfile(file)):
            print ("file not found: {}".format(file))
            sys.exit(0)

    infile = open(args.fingerprint)
    jsondata = json.load(infile)
    data = jsondata[node]
    df = pd.DataFrame(data, columns=['ip'])
        
    df.drop_duplicates('ip', keep='first', inplace=True)
    df['src_net'] =  df.ip.str.extract('(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)\\d{1,3}')+"0"
    df['ip'] = df['ip'].apply(lambda x: ipaddr.IPv4Address(x))

    print ('ips found: ', len(df['ip'])) 
    
    infile.close()

    return df
#------------------------------------------------------------------------------
def find_ip_proto(args):

    file = args.fingerprint
    if (args.fingerprint):
        file = args.fingerprint
        if not (os.path.isfile(file)):
            print ("file not found: {}".format(file))
            sys.exit(0)

    infile = open(args.fingerprint)
    jsondata = json.load(infile)
    data = jsondata[nodeproto4]
    df = pd.DataFrame(data, columns=['ip_proto'])
        
    df.drop_duplicates('ip_proto', keep='first', inplace=True)

    print ('ip_proto table size: ', len(df['ip_proto'])) 
    
    infile.close()

    return df

#------------------------------------------------------------------------------
def find_high_proto(args):

    file = args.fingerprint
    if (args.fingerprint):
        file = args.fingerprint
        if not (os.path.isfile(file)):
            print ("file not found: {}".format(file))
            sys.exit(0)

    infile = open(args.fingerprint)
    jsondata = json.load(infile)
    data = jsondata[nodeproto7]
    df = pd.DataFrame(data, columns=['high_proto'])
        
    df.drop_duplicates('high_proto', keep='first', inplace=True)

    print ('high_proto table size: ', len(df['high_proto'])) 
    
    infile.close()

    return df

#------------------------------------------------------------------------------
def find_dstport(args):

    file = args.fingerprint
    if (args.fingerprint):
        file = args.fingerprint
        if not (os.path.isfile(file)):
            print ("file not found: {}".format(file))
            sys.exit(0)

    infile = open(args.fingerprint)
    jsondata = json.load(infile)
    data = jsondata[nodedport]
    df = pd.DataFrame(data, columns=['dstport'])
        
    df.drop_duplicates('dstport', keep='first', inplace=True)

    print ('dstport table size: ', len(df['dstport'])) 
    
    infile.close()

    return df

#------------------------------------------------------------------------------
def smart_aggregate(df):

    grouped = df.groupby('src_net')['ip']
    all_networks = []
    for name, group in grouped:
        
        # more than one IP in the /24 subnet, try to summarize
        if (len(group)>1):        

            # sort list
            ip_lst = sorted(group.reset_index()['ip'].to_list())
            lowest_ip  = ip_lst[0]  
            highest_ip = ip_lst[-1] 
            
            # split the list of IPs from the same subnet in tuple
            lst_with_two_elements = []
            for i in range(0, len(ip_lst), 2):
                lst_with_two_elements.append(ip_lst[i : i+2])
             
            # try to summarize the IP range 
            # get range every two ips
            for sub_lst in (lst_with_two_elements):
    
                # sub_lst is even, so we can summarize
                if (((len(sub_lst))% 2) == 0):
                    lowest_ip = sub_lst[0]
                    highest_ip  = sub_lst[1]
                    mask_length = ipaddr._get_prefix_length(int(lowest_ip), int(highest_ip), lowest_ip.max_prefixlen)
                    network_ip = ipaddr.IPNetwork("{}/{}".format(lowest_ip, mask_length)).network
                    network = ipaddr.IPNetwork("{}/{}".format(network_ip, mask_length), strict = True)
                    all_networks.append(network)
                    
                # there is no range to merge
                else:
                    network = ipaddr.IPNetwork("{}/{}".format(sub_lst[0], 32), strict = True)
                    all_networks.append(network)
    print ('total subnets: ', len(all_networks))    
    return all_networks

#------------------------------------------------------------------------------
def to_string(s):
    try:
        return str(s)
    except:
        #Change the encoding type if needed
        return s.encode('utf-8')

#------------------------------------------------------------------------------
def reduce_item(key, value):
    #global reduced_item
    
    #Reduction Condition 1
    if type(value) is list:
        i=0
        for sub_item in value:
            reduce_item(key+'_'+to_string(i), sub_item)
            i=i+1

    #Reduction Condition 2
    elif type(value) is dict:
        sub_keys = value.keys()
        for sub_key in sub_keys:
            reduce_item(key+'_'+to_string(sub_key), value[sub_key])
    
    #Base Condition
    else:
        reduced_item[to_string(key)] = to_string(value)

#------------------------------------------------------------------------------
def _attribute(category, atype, value, comment):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = atype
    attribute.value = value
    attribute.comment = comment
    return attribute

#------------------------------------------------------------------------------
def add_attributes_ips(misp, event, ips):

    # create ipset

    for ip in ips:
        #print('processing ', ip)
        value = to_string(ip)
        print ('adding value: ', value)
        comment = 'attacker ip'
        misp.add_attribute(event, _attribute('Network activity', 'ip-src', value, comment), pythonify=True)
        
#------------------------------------------------------------------------------
def add_attributes_subnets(misp, event, all_networks):

    for net in all_networks:
        print('processing ', net)
        value = to_string(net)
        print ('adding value: ', value)
        comment = 'attacker subnet'
        misp.add_attribute(event, _attribute('Network activity', 'ip-src', value, comment), pythonify=True)

#------------------------------------------------------------------------------
def add_attributes_ipsamp(misp, event, ips):

    # create ipset

    for ip in ips:
        #print('processing ', ip)
        value = to_string(ip)
        print ('adding value: ', value)
        comment = 'amplifier ip'
        misp.add_attribute(event, _attribute('Network activity', 'ip-src', value, comment), pythonify=True)
        
#------------------------------------------------------------------------------
def add_attributes_subnetsamp(misp, event, all_networks):

    for net in all_networks:
        print('processing ', net)
        value = to_string(net)
        print ('adding value: ', value)
        comment = 'amplifier subnet'
        misp.add_attribute(event, _attribute('Network activity', 'ip-src', value, comment), pythonify=True)

#------------------------------------------------------------------------------
def add_attributes_ports(misp, event, dport):

    for dp in dport:
        print('processing ', dp)
        value = to_string(dp)
        print ('adding value: ', value)
        comment = 'destination port of attack'
        misp.add_attribute(event, _attribute('Network activity', 'port', value, comment), pythonify=True)
        
#------------------------------------------------------------------------------
def add_attributes_proto4(misp, event, proto4):

    for p in proto4:
        print('processing ', p)
        value = to_string(p)
        print ('adding value: ', value)
        comment = '4 level protocol of attack'
        misp.add_attribute(event, _attribute('Network activity', 'other', value, comment), pythonify=True)
        
#------------------------------------------------------------------------------
def add_attributes_proto7(misp, event, proto7):

    for p in proto7:
        print('processing ', p)
        value = to_string(p)
        print ('adding value: ', value)
        comment = 'higher level protocol of attack'
        misp.add_attribute(event, _attribute('Network activity', 'other', value, comment), pythonify=True)
        
#------------------------------------------------------------------------------
def add_attributes_from_json(misp, event, input_file):

    # add all ips in a json file
    infile = open(input_file, 'r')
    json_value = infile.read()
    raw_data = json.loads(json_value)

    try:
        data_to_be_processed = raw_data[node]
        print(1)
    except:
        #data_to_be_processed = raw_data
        print('wrong node')
        sys.exit(0)

    i = 1
        
    for row in data_to_be_processed:
        #print(str(row))
        value = str(row)
        print(value)
        comment = 'attacker ip'
        misp.add_attribute(event, _attribute('Network activity', 'ip-src', value, comment), pythonify=True)
        i += 1

    print('added ', i, ' attributes')
    infile.close()

# Main 
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    parser = parser_args()
    args = parser.parse_args()

    if (args.fingerprint):
        jfile = args.fingerprint
        if not (os.path.isfile(jfile)):
            print ("file not found: {}".format(jfile))
            sys.exit(0)

    if args.node:
        node = args.node

    if args.misp_url:
        misp_url = args.misp_url

    if args.misp_apikey:
        misp_key = args.misp_apikey

    if args.distribution:
        distribution = args.distribution

    if args.event_info:
        event_info = args.event_info

    if args.analysis_level:
        analysis_level = args.analysis_level

    if args.threat_level:
        threat_level = args.threat_level

    if args.subnets:
        addips = False

    with open(jfile, 'rb', 0) as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'attackers') != -1:
            print('attackers found')
            att = True
        if s.find(b'amplifiers') != -1:
            print('amplifiers found')
            amp = True
            
    #find attackers
    if (att == True):
        df = find_ips(args, node)
        no_of_ips = len(df['ip'])
        subnets = smart_aggregate(df)
        no_of_nets = len(subnets)
        
    #find amplifiers
    if (amp == True):
        dfa = find_ips(args, nodeamp)
        no_of_amp = len(dfa['ip'])
        subnetsa = smart_aggregate(dfa)
        no_of_netsa = len(subnetsa)

    proto4 = find_ip_proto(args)
    no_of_ip_proto = len(proto4['ip_proto'])
    proto7 = find_high_proto(args)
    no_of_high_proto = len(proto7['high_proto'])
    dport = find_dstport(args)
    no_of_dstport = len(dport['dstport'])
    
    print("Fingerprint processed: {}".format(args.fingerprint))
    if (att == True):
        print("IPs found: {}".format(len(df['ip'])))
        print("The IPs were summarized in: {} subnets".format(len(subnets)))
    if (amp == True):
        print("Amplifier IPs found: {}".format(len(dfa['ip'])))
        print("The IPs were summarized in: {} subnets".format(len(subnetsa)))

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    event = MISPEvent()
    event.distribution = distribution
    event.threat_level_id = threat_level
    event.analysis = analysis_level
    event.info = event_info

    event = misp.add_event(event, pythonify=True)
    #add attributes 
    #we may prefer to do: if no of ips < N add ips else add subnets, where N is a cmd line arg
    if (att == True): 
        if (addips):
            print ('adding ', no_of_ips,  ' ips')
            #add_attributes_from_json(misp, event, jfile)
            add_attributes_ips(misp, event, df['ip'])
        else:
            print ('adding ', no_of_nets, ' subnets')
            add_attributes_subnets(misp, event, subnets)
    if (amp == True):
        if (addips):
            amp = True
            print ('adding ', no_of_amp,  ' amplfier ips')
            #add_attributes_from_json(misp, event, jfile)
            add_attributes_ipsamp(misp, event, dfa['ip'])
        else:
            print ('adding ', no_of_netsa, ' subnets')
            add_attributes_subnetsamp(misp, event, subnetsa)
    else:
        print('neither attackers nor amplifiers are present')


    #add other attributes
    add_attributes_ports(misp, event, dport['dstport'])
    add_attributes_proto4(misp, event, proto4['ip_proto'])
    add_attributes_proto7(misp, event, proto7['high_proto'])

    #add/upload json file to the event
    p = Path(args.fingerprint)
    a = MISPAttribute()
    a.type = 'attachment'
    a.value = p.name
    a.data = p
    a.comment = 'DDoS fingerprint json file generated by dissector'
    misp.add_attribute(event, a)
    
    if (att == True):
        misp.tag(event,'ddos attack',False) 
    misp.tag(event,'validated',False) 
    if (amp == True):
        misp.tag(event,'ddos amplification attack',False) 

    #print('publish the event')
    misp.publish(event)
    headers = {
    'Authorization': 'misp automation key',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    }
    eventids = str(event.id)
    urlsnort = 'https://misp.url/events/restSearch/returnFormat:snort/eventid:' + eventids + '/'
    response = requests.get(urlsnort, headers=headers)
    snortfile = 'snort_rules_' + eventids + '.txt'
    open(snortfile,'wb').write(response.content)
    
    print('*****')
    print('event published at: https://misp.url/events/view/' + eventids)
    print('*****')
    print('snort rule downloaded in: ' + snortfile)
    print('*****')

    print('***end***')
