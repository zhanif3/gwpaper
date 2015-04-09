import ujson
import api
import sys
import os
import numpy

"""
Age of domain
age of ns
ns is self hosted, or part of a third party
whois proxy?
country of ns
country of domain (a record)
TTL of ns
ttl of a
number of record types present
how unique are the email address
entropy of email addresses
is the "user" part of the email same as the domain?
ns and domain same tld
whois geo in same country as A or NS records
are the NS's on the same 2ld
"""
keyset = set()


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
    for line in open('analysis_results').readlines():
        js = ujson.loads(line.strip())
        if js['service_name'] == 'chompy':
            for element in js['results']:
                if element['result'] == 'Raw':
                    js['parsed_whois'] = api.parse_whois(element.get('Value', {}))
                    for contact_type in js.get('parsed_whois', {}).get('contacts', []):
                        key = '%s_address_verification' % (contact_type)
                        v = api.verify_address(js['parsed_whois']['contacts'][contact_type])
                        if "error" not in v:
                            js[key] = v
                        email_key = '%s_freemail_verification' % (contact_type)
                        if js.get('parsed_whois', {}).get('contacts', {}).get(contact_type, {}) is not None:
                            js[email_key] = api.verify_freemail(
                                js.get('parsed_whois', {}).get('contacts', {}).get(contact_type, {}).get('email', ''))
                if element['subtype'] == 'A':
                    # total_num, ttl oddity, number of asns, asn/ip ratio, ttl/ip ratio? num unique ttls?
                    js['total_a_records'] = js.get('total_a_records', 0) + 1
                    if js.get('a_ttls', []) is not None:
                        js['a_ttls'] = js.get('a_ttls', []).append(element.get('ttl', -1))
                    if js.get('a_asns', []) is not None:
                        if len(element.get('ASN', [])) > 0:
                            js['a_asns'] = js.get('a_asns', []).append(element.get('ASN', {}).get('asn', None))
                    if js.get('num_asn_peers', 0) is not None:
                        if len(element.get('ASN', [])) > 0:
                            js['num_asn_peers'] = js.get('num_asn_peers', 0) + len(element.get('ASN', {}).get('as_peers', []))
                    r = api.check_vt_ip(element['result'])

                    if r['response_code'] == 1:
                        if r.get('detected_urls') is not None:
                            js['detected_urls_reputation'] = js.get('detected_urls_reputation', []) + [float(res['positives']) / float(res['total']) for res in r.get('detected_urls', {'positives':0, 'total':54})]
                        else:
                            js['detected_urls_reputation'] = [-1]

                        if r.get('detected_communicating_samples') is not None:
                            js['communicating_sample_reputation'] = js.get('communicating_sample_reputation', []) + [float(res['positives']) / float(res['total']) for res in r.get('detected_communicating_samples', {'positives':0, 'total':54})]
                        else:
                            js['communicating_sample_reputation'] = [-1]

                        if r.get('detected_downloaded_samples') is not None:
                            js['downloaded_sample_reputation'] = js.get('downloaded_sample_reputation', []) + [float(res['positives']) / float(res['total']) for res in r.get('detected_downloaded_samples', {'positives':0, 'total':54})]
                        else:
                            js['downloaded_sample_reputation'] = [-1]
                    else:
                        print 'RCODE', r['response_code']
                #if element['subtype'] == 'NS':
                #    js['total_ns_records'] = js.get('total_ns_records', 0) + 1
                #    check_vt_ip()
            keyset.update(dict(flattenDict(js)).keys())
            print keyset
            #print numpy.mean(numpy.array(js['downloaded_sample_reputation'])), numpy.median(numpy.array(js['downloaded_sample_reputation']))
            #print js['detected_urls_reputation'], js['communicating_sample_reputation'], js['downloaded_sample_reputation']
