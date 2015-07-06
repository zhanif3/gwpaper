import api
import numpy
import os
import sys
import ujson
from pymongo import MongoClient
from bson.objectid import ObjectId

client = MongoClient()

db = client['crits']
analysis_collection = db['analysis_results']
sample_collection = db['sample']

# Helper dictionary for finding chompy analysis 
analysis_query = {
    "service_name": "chompy",
    "status": "completed",
    "object_type": "Domain"
}

# Helper for finding TLO with the sources we care about. 
sample_query = {
	"source.name": { "$in": ["maltrieve", "novetta", "benign"] }
}

def flattenDict(d, result=None):
    if result is None:
        result = {}
    for key in d:
        value = d[key]
        if isinstance(value, dict):
            value1 = {}
            for keyIn in value:
                value1[".".join([key, keyIn])] = value[keyIn]
            flattenDict(value1, result)
        elif isinstance(value, (list, tuple)):
            for indexB, element in enumerate(value):
                if isinstance(element, dict):
                    value1 = {}
                    index = 0
                    for keyIn in element:
                        newkey = ".".join([key, keyIn])
                        value1[".".join([key, keyIn])] = value[indexB][keyIn]
                        index += 1
                    for keyA in value1:
                        flattenDict(value1, result)
        else:
            result[key] = value
    return result

if __name__ == '__main__':

	# I am moving through the analysis results first as they will be fewer
	# the way the data is stored also makes this easier to link back to an obj_ID
	for analysis in analysis_results.find(analysis_query):

		# Check to see if we care about that sample based on its source. 
	    sample = samples.find_one( sample_query.update( {"_id": ObjectId(analysis["object_id"])}) )
	    if sample:
	    	# Found a sample we care about so begin feature extraction
		    result = {}
		    try:
		    	for element in analysis['results']:
		    		# Pull DNS Summary information
		    		if element['subtype'] == 'DNS Summary':
		    			result['domain'] = element['result']
                        result['domain_length'] = len(element['result'])

                        record_types = element.get('Record Contains', "").split(',')
                        print record_types
                        result['num_record_types'] = len(record_types)
                        for ty in record_types:
                            result[ty.strip()] = 1

                    #Pull A record and attached ASN information
                    if element['subtype'] == 'A':
                        result['total_a_records'] = result.get('total_a_records', 0) + 1
                        dns = element.get('DNS', {})
                        asn = element.get('ASN', {})

                        a_ttls = result.get('a_ttls', [])
                        a_ttls.append(dns.get('ttl', -1))
                        result['a_ttls'] = a_ttls
                        a_asns = result.get('a_asns', [])

                        if isinstance(asn, list):
                            asn = {}

                        a_asns.append(asn.get('asn', None))
                        result['a_asns'] = a_asns
                        asn_peers = result.get('asn_peers', [])
                        asn_peers.append(asn.get('as_peers', []))
                        result['asn_peers'] = asn_peers

                    if element['result'] == 'Raw':
                        # We'll do a flatten() on this, as manually extracting the data will be painful.
                        result['parsed_whois'] = api.parse_whois(element.get('Value', {}))
                        result['raw_whois_len'] = len(element.get('Value', {}))

		    except TypeError:
		        pass
		    except:
		        print(sys.exc_info())