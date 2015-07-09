#!/usr/bin/env python3

import argparse
import itertools
import logging
import math
import multiprocessing
import numpy
import sys

import api
from pymongo import MongoClient
from bson.objectid import ObjectId
from multiprocessing import Pool, Lock

FIELDS_TO_WRITE = ['NS', 'A', 'SOA', 'MX', 'TXT', "total_a_records",
                   "num_asn_peers", "total_unique_peers",
                   "median_peers_per_asn", "mean_peers_per_asn mean_ttl",
                   "median_ttl", "total_unique_ttls",
                   "num_contacts subdomains", "asn_ip_ratio",
                   "asn_peer_ip_ratio", 'domain_length',
                   'num_record_types', 'raw_whois_len', 'total_a_records',
                   'pdns_a_records', 'total_urls', 'num_url_scores',
                   'num_detected_communicating_scores',
                   'num_detected_downloaded_scores', 'mean_url_scores',
                   'mean_detected_communicating_scores',
                   'mean_detected_downloaded_scores', 'median_url_scores',
                   'median_detected_communicating_scores',
                   'median_detected_downloaded_scores']



def emit(result):
    fields = FIELDS_TO_WRITE
    output = []
    asn_peers = result.get('asn_peers', [])
    result['num_asn_peers'] = len(list(itertools.chain.from_iterable(asn_peers)))
    result['total_unique_peers'] = len(set(itertools.chain.from_iterable(asn_peers)))
    result['median_peers_per_asn'] = numpy.median([len(item) for item in asn_peers])

    if math.isnan(result['median_peers_per_asn']):
        result['median_peers_per_asn'] = 0

    result['mean_peers_per_asn'] = numpy.mean([len(item) for item in asn_peers])

    if math.isnan(result['mean_peers_per_asn']):
        result['mean_peers_per_asn'] = 0

    ttls = result.get("a_ttls", [])
    result['mean_ttl'] = numpy.mean(numpy.array(ttls))

    if math.isnan(result['mean_ttl']):
        result['mean_ttl'] = -1
    result['median_ttl'] = numpy.median(numpy.array(ttls))

    if math.isnan(result['median_ttl']):
        result['median_ttl'] = -1

    result['total_unique_ttls'] = len(set(ttls))

    result['num_contacts'] = len(result.get("contacts", []))
    result['subdomains'] = len(result.get('domain', '').strip('.').split())

    try:
        result['asn_ip_ratio'] = (len(result.get('a_asns', [])) /
                                  float(result.get('total_a_records', 0)))
    except ZeroDivisionError:
        result['asn_ip_ratio'] = -1

    try:
        result['asn_peer_ip_ratio'] = (result['num_asn_peers'] /
                                       float(result.get('total_a_records', 0)))
    except ZeroDivisionError:
        result['asn_peer_ip_ratio'] = -1

    for field in fields:
        dat = result.get(field, -1)
        if math.isnan(dat):
            dat = field+"NAN"
        output.append(dat)

    return (output, result['domain'], result['source'])


# normally i'm totally against any global variables
# but the multiprocessing serialization forces me to
file_write_lock = Lock()
sample_collection = None
output_file = None


def analyze(analysis):
    global sample_collection
    global output_file

    result = dict()

    # Check to see if we care about that sample based on its source.
    sample = sample_collection.find_one({
        "_id": ObjectId(analysis["object_id"])
    })

    source_name = sample["source"][0]["name"]
    if source_name in {"benign", "maltrieve", "novetta"}:
        result["source"] = source_name
    else:
        # this sample isn't interesting for us
        return

    # Found a sample we care about so begin feature extraction
    try:
        for element in analysis['results']:
            # Pull DNS Summary information
            if element['subtype'] == "DNS Summary":
                result['domain'] = element['result']
                result['domain_length'] = len(element['result'])

                record_types = element.get('Record Contains', "").split(',')
                logging.info("record types: {}".format(record_types))
                result['num_record_types'] = len(record_types)
                result.update({k.strip(): 1 for k in record_types})

            # Pull A record and attached ASN information
            elif element['subtype'] == 'A':
                result['total_a_records'] = result.get('total_a_records', 0) + 1
                dns = element.get('DNS', {})
                asn = element.get('ASN', {})

                a_ttls = result.get('a_ttls', [])
                a_ttls.append(dns.get('ttl', -1))
                result['a_ttls'] = a_ttls
                a_asns = result.get('a_asns', [])

                if isinstance(asn, list):
                    asn = dict()

                a_asns.append(asn.get('asn', None))
                result['a_asns'] = a_asns
                asn_peers = result.get('asn_peers', [])
                asn_peers.append(asn.get('as_peers', []))
                result['asn_peers'] = asn_peers

            if element['result'] == 'Raw':
                # We'll do a flatten() on this, as manually extracting the data will be painful.
                result['parsed_whois'] = api.parse_whois(element.get('Value', {}))
                result['raw_whois_len'] = len(element.get('Value', {}))

                for contact_type in result.get('parsed_whois', {}).get('contacts', []):
                    key = '%s_address_verification' % (contact_type)
                    v = api.verify_address(result['parsed_whois']['contacts'][contact_type])
                    if "error" not in v:
                        result[key] = v

                    email_key = '%s_freemail_verification' % (contact_type)
                    contact = result.get('parsed_whois', {}).get('contacts', {}).get(contact_type, {})
                    if contact is not None:
                        result[email_key] = api.verify_freemail(contact.get('email', ''))

    except TypeError:
        logging.error("type error when gathering database values!")
    except Exception as _:
        logging.error(("exception when gathering "
                       " database values:\n{}".format(sys.exc_info())))

    data_result = emit(result)
    with file_write_lock:
        logging.info("data result: {}".format(data_result))
        output_file.write("{}\n".format(data_result))


def main():
    global sample_collection
    global output_file

    cmd = argparse.ArgumentParser()
    cmd.add_argument("output_file", type=argparse.FileType('w'),
                     help="file where to write results in")
    cmd.add_argument("--jobs", "-j", default=multiprocessing.cpu_count(),
                     help="file where to write results in")
    cmd.add_argument("--multiprocess", "-m", action="store_true",
                     help="use multiple processes for parallelization")

    args = cmd.parse_args()

    # set logging format and level
    logging.basicConfig(format='%(asctime)s => %(levelname)s: %(message)s',
                        level=logging.INFO)

    # silence requests-messages
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # the database client
    client = MongoClient()

    # connect to databases
    db = client['crits']
    analysis_collection = db['analysis_results']
    sample_collection = db['domains']

    # Helper dictionary for finding chompy analysis
    analysis_query = {
        "service_name": "chompy",
        "status": "completed",
        "object_type": "Domain"
    }

    # Helper for finding TLO with the sources we care about.
    sample_query = {
        "source.name": {
            "$in": ["maltrieve", "novetta", "benign"]
        }
    }


    # I am moving through the analysis results first as they will be fewer
    # the way the data is stored also makes this easier to link back to an
    # obj_ID
    to_analyze = analysis_collection.find(analysis_query)
    sample_count = to_analyze.count()
    output_file = args.output_file
    logging.info("will run over {} samples".format(sample_count))

    if args.multiprocess:
        logging.info("using multiprocessing")
        with Pool(processes=args.jobs) as pool:
            pool.map(analyze, to_analyze)
            pool.close()
            pool.join()

    else:
        logging.info("using a single thread")
        for v in to_analyze:
            analyze(v)


if __name__ == '__main__':
    main()
