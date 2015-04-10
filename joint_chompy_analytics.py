import ujson
import api
import numpy
import itertools
"""
[{"status": "completed", "analysis_id": "be0a9ebf-8cd1-4895-a3eb-63fed8ccdef0", "finish_date": "2015-03-12 19:15:51.819539", "service_name": "chompy", "object_type": "Domain", "distributed": false,
"results": [{"Authoritive Nameserver": "ns1.qhoster.net., ns2.qhoster.net., ns4.qhoster.net., ns3.qhoster.net.", "subtype": "DNS Summary", "result": "garagemapp.com", "Date": "2015-03-12 19:15:50.554718",
"Record Contains": "NS, A, SOA, MX", "Name Server Queried": "8.8.4.4"}, {"subtype": "NS", "result": "ns2.qhoster.net.", "ttl": 21599, "type": "NS", "class": "IN", "expiration": 1426205749.172549},
{"subtype": "NS", "result": "ns4.qhoster.net.", "ttl": 21599, "type": "NS", "class": "IN", "expiration": 1426205749.172549},
{"subtype": "NS", "result": "ns1.qhoster.net.", "ttl": 21599, "type": "NS", "class": "IN", "expiration": 1426205749.172549},
{"subtype": "NS", "result": "ns3.qhoster.net.", "ttl": 21599, "type": "NS", "class": "IN", "expiration": 1426205749.172549},
{"subtype": "A", "result": "154.43.166.88", "DNS": {"ttl": 14400, "type": "A", "class": "IN", "expiration": 1426198550.451865},
"ASN": {"cc": "US", "asn": "174", "data_allocated": "", "registry": "arin", "bgp_prefix": "154.43.164.0/22", "as_peers": ["286", "1273", "1299", "2914", "3257", "3356", "22822"],
"as_name": "COGENT-174 - Cogent Communications,US"}}, {"retry": 7200, "mname": "ns1.qhoster.net.", "refresh": 86400, "subtype": "SOA", "minimum": 86400,
"result": "admin.qhoster.com.", "expire": 3600000, "ttl": 86400, "serial": 2015022803, "type": "SOA", "class": "IN", "expiration": 1426270550.513004},
{"result": "garagemapp.com.", "subtype": "MX", "expiration": 1426198550.534705, "ttl": 14400, "type": "MX", "class": "IN", "preference": 0},
{"subtype": "WHOIS", "result": "Parsed", "Value": {"domain": "garagemapp.com", "data": {"ac": "br", "ns": ["ns3.qhoster.net", "ns2.qhoster.net", "ns4.qhoster.net", "ns1.qhoster.net"],
"ae": ["charles.buffet2015@bol.com.br"], "d": "garagemapp.com", "no": false, "m": true, "s": ["clientupdateprohibited", "clientrenewprohibited", "clientdeleteprohibited", "clienttransferprohibited"],
"cd": "2016-02-28", "rd": "2015-03-01", "re": ["charles.buffet2015@bol.com.br"], "tl": "com", "r": "namesilo", "rc": "br", "qh": "9c69ea97b702742e9f74f476809e0ff8", "te": ["charles.buffet2015@bol.com.br"],
"tc": "br"}, "time": "2015-03-07T16:55:04.34Z"}}, {"subtype": "WHOIS", "result": "Raw", "Value": "Domain Name: garagemapp.com\nRegistry Domain ID: 1906274101_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.namesilo.com\nRegistrar URL: https://www.namesilo.com/\nUpdated Date: 2015-03-01\nCreation Date: 2015-02-28\nRegistrar Registration Expiration Date: 2016-02-28\nRegistrar: NameSilo, LLC\nRegistrar IANA ID: 1479\nRegistrar Abuse Contact Email: abuse@namesilo.com\nRegistrar Abuse Contact Phone: +1.6024928198\nReseller: QHOSTER.COM\nStatus: clientUpdateProhibited\nStatus: clientRenewProhibited\nStatus: clientDeleteProhibited\nStatus: clientTransferProhibited\nRegistry Registrant ID: \nRegistrant Name: Charles Francisco\nRegistrant Organization: \nRegistrant Street: Avenida Paulista \nRegistrant City: Sao Paulo\nRegistrant State/Province: SP\nRegistrant Postal Code: 01310300\nRegistrant Country: BR\nRegistrant Phone: +55.551135439899\nRegistrant Phone Ext: \nRegistrant Fax: \nRegistrant Fax Ext: \nRegistrant Email: charles.buffet2015@bol.com.br\nRegistry Admin ID: \nAdmin Name: Charles Francisco\nAdmin Organization: \nAdmin Street: Avenida Paulista \nAdmin City: Sao Paulo\nAdmin State/Province: SP\nAdmin Postal Code: 01310300\nAdmin Country: BR\nAdmin Phone: +55.551135439899\nAdmin Phone Ext: \nAdmin Fax: \nAdmin Fax Ext: \nAdmin Email: charles.buffet2015@bol.com.br\nRegistry Tech ID: \nTech Name: Charles Francisco\nTech Organization: \nTech Street: Avenida Paulista \nTech City: Sao Paulo\nTech State/Province: SP\nTech Postal Code: 01310300\nTech Country: BR\nTech Phone: +55.551135439899\nTech Phone Ext: \nTech Fax: \nTech Fax Ext: \nTech Email: charles.buffet2015@bol.com.br\nName Server: NS1.QHOSTER.NET\nName Server: NS2.QHOSTER.NET\nName Server: NS3.QHOSTER.NET\nName Server: NS4.QHOSTER.NET\nDNSSEC: unSigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\nLast update of WHOIS database: 2015-03-07 09:55:04\n\nNOTICE AND TERMS OF USE: You are not authorized to access or query our WHOIS\ndatabase through the use of high-volume, automated, electronic processes. The\nData in our WHOIS database is provided for information purposes only, and to\nassist persons in obtaining information about or related to a domain name\nregistration record. We do not guarantee its accuracy. By submitting a WHOIS\nquery, you agree to abide by the following terms of use: You agree that you may\nuse this Data only for lawful purposes and that under no circumstances will you\nuse this Data to: (1) allow, enable, or otherwise support the transmission of\nmass unsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes that\napply to us (or our computer systems). The compilation, repackaging,\ndissemination or other use of this Data is expressly prohibited without our\nprior written consent. We reserve the right to terminate your access to the\nWHOIS database at our sole discretion, including without limitation, for\nexcessive querying of the WHOIS database or for failure to otherwise abide by\nthis policy. We reserve the right to modify these terms at any time.\n\n\n\nWWW.QHOSTER.COM - CHEAP DOMAINS, HOSTING, LINUX / WINDOWS VPS, DEDICATED SERVERS - PAYPAL, WEBMONEY, PERFECT MONEY, BITCOIN, PAYZA, SKRILL, CASHU, UKASH, OKPAY, EGOPAY, PAYSAFECARD, NETELLER ETC.\n\n\n\n"}, {"subtype": "Chompy Information", "domain": "garagemapp.com", "last_trained": "date", "result": 0}], "schema_version": 1, "start_date": "2015-03-12 19:15:50.064861", "source": null, "version": "1.0.0", "object_id": "5501d7d5ad951d0b78d7fa7f", "template": null, "_id": {"$oid": "5501d7d6ad951d0b78d7fa83"}, "config": {"nameservers": ["8.8.8.8", "8.8.4.4"], "novetta_api_key": "EuBAaAE9LWzUhxpTkVVc", "novetta_url": "https://whois-api", "sigfiles": ["ye_all.yar"]}, "analyst": "maltrieve", "log": [{"message": "Starting Analysis", "level": "info", "datetime": "2015-03-12 19:15:50.089914"}, {"message": "For garagemapp.com using nameserver 8.8.4.4", "level": "info", "datetime": "2015-03-12 19:15:50.090273"}, {"message": "NS : Queried garagemapp.com successfully!\nAAAA : The response did not contain a answer for garagemapp.com.\nCNAME : The response did not contain a answer for garagemapp.com.\nTXT : The response did not contain a answer for garagemapp.com.", "level": "info", "datetime": "2015-03-12 19:15:50.554588"}, {"message": "Gathered whois!", "level": "info", "datetime": "2015-03-12 19:15:51.802541"}, {"message": "Analysis complete", "level": "info", "datetime": "2015-03-12 19:15:51.803103"}]}, {"status": "completed", "analysis_id": "64bcccc5-8e21-473e-911d-2a118c388aad", "finish_date": "2015-03-12 19:15:51.025115", "service_name": "virustotal_lookup", "object_type": "Domain", "distributed": false, "results": [{"subtype": "A Records", "last_resolved": "2015-03-03 00:00:00", "result": "154.43.166.88"}], "schema_version": 1, "start_date": "2015-03-12 19:15:49.894174", "source": null, "version": "3.1.0", "object_id": "5501d7d5ad951d0b78d7fa7f", "template": null, "_id": {"$oid": "5501d7d5ad951d0b78d7fa81"}, "config": {"vt_query_url": "https://www.virustotal.com/vtapi/v2/file/report", "vt_network_url": "https://www.virustotal.com/vtapi/v2/file/network-traffic", "vt_add_domains": true, "vt_domain_url": "https://www.virustotal.com/vtapi/v2/domain/report", "vt_add_pcap": false, "vt_ip_url": "https://www.virustotal.com/vtapi/v2/ip-address/report", "sigfiles": ["ye_all.yar"], "vt_api_key_private": true}, "analyst": "maltrieve", "log": [{"message": "Starting Analysis", "level": "info", "datetime": "2015-03-12 19:15:49.921328"}, {"message": "URL information not included in VT response.\nCategory information not included in VT response.\nDetected communicating sample information not included in VT response.\nUndetected communicating sample information not included in VT response.\nDownloaded sample information not included in VT response.\nUndetected domain sample information not included in VT response.", "level": "info", "datetime": "2015-03-12 19:15:51.007814"}, {"message": "Analysis complete", "level": "info", "datetime": "2015-03-12 19:15:51.007952"}]}, {"status": "completed", "analysis_id": "58264c72-8dc0-41cc-9a52-556c03282061", "finish_date": "2015-03-12 19:15:51.380053", "service_name": "threatrecon_lookup", "object_type": "Domain", "distributed": false, "results": [{"comment": "", "indicator": "garagemapp.com", "attribution": "", "reference": "https://lists.malwarepatrol.net/cgi/getfile?receipt=f1377916320&product=8&list=smoothwall", "root_node": "", "source": "Wapack_OSINT", "country": "", "rrname": "", "confidence": 70, "id": 14556068, "subtype": "Enrichment Data", "result": "garagemapp.com", "killchain": "NA", "first_seen": "2015-03-04", "processtype": "Direct", "rrdata": "", "tags": "", "last_seen": "2015-03-04"}, {"comment": "", "indicator": "154.43.166.88", "attribution": "", "reference": "https://lists.malwarepatrol.net/cgi/getfile?receipt=f1377916320&product=8&list=smoothwall", "root_node": "garagemapp.com", "source": "Wapack_OSINT", "country": "United States", "rrname": "", "confidence": 70, "id": 14556069, "subtype": "Enrichment Data", "result": "154.43.166.88", "killchain": "NA", "first_seen": "2015-03-04", "processtype": "Derived_pDNS", "rrdata": "", "tags": "", "last_seen": "2015-03-04"}], "schema_version": 1, "start_date": "2015-03-12 19:15:50.001851", "source": null, "version": "1.0.0", "object_id": "5501d7d5ad951d0b78d7fa7f", "template": null, "_id": {"$oid": "5501d7d6ad951d0b78d7fa82"}, "config": {"sigfiles": ["ye_all.yar"], "tr_query_url": "https://api.threatrecon.co/api/v1/search"}, "analyst": "maltrieve", "log": [{"message": "Starting Analysis", "level": "info", "datetime": "2015-03-12 19:15:50.027933"}, {"message": "Analysis complete", "level": "info", "datetime": "2015-03-12 19:15:51.365720"}]}]

"""
keyset = set()

if __name__ == '__main__':
    for line in open('joint_vt_chompy').readlines():
        js = ujson.loads(line)
        result = {}
        for e in js:
            if e['service_name'] == 'chompy':
                for element in e['results']:
                    if element['subtype'] == "DNS Summary":
                        record_types = element.get('Record Contains', "").split(',')
                        result['num_record_types'] = len(record_types)
                        for ty in record_types:
                            result[ty] = 1

                    if element['result'] == 'Raw':
                        # We'll do a flatten() on this, as manually extracting the data will be painful.
                        result['parsed_whois'] = api.parse_whois(element.get('Value', {}))
                        result['raw_whois_len'] = len(element.get('Value', {}))
                        """
                        for contact_type in result.get('parsed_whois', {}).get('contacts', []):
                            key = '%s_address_verification' % (contact_type)
                            v = api.verify_address(result['parsed_whois']['contacts'][contact_type])
                            if "error" not in v:
                                result[key] = v

                            email_key = '%s_freemail_verification' % (contact_type)
                            contact = result.get('parsed_whois', {}).get('contacts', {}).get(contact_type, {})
                            if contact is not None:
                                result[email_key] = api.verify_freemail(contact.get('email', ''))
                        """
                    if element['subtype'] == 'A':
                        # total_num, ttl oddity, number of asns, asn/ip ratio, ttl/ip ratio? num unique ttls?
                        result['total_a_records'] = e.get('total_a_records', 0) + 1
                        dns = element.get('DNS', {})
                        asn = element.get('ASN', {})

                        a_ttls = result.get('a_ttls', [])
                        a_ttls.append(dns.get('ttl', -1))
                        result['a_ttls'] = a_ttls

                        a_asns = result.get('a_asns', [])
                        a_asns.append(asn.get('asn', None))
                        result['a_asns'] = a_asns
                        asn_peers = result.get('num_asn_peers', [])
                        asn_peers.append(asn.get('as_peers', []))
                        result['num_asn_peers'] = asn_peers
                        result['total_unique_peers'] = len(set(itertools.chain.from_iterable(asn_peers)))
                        result['median_peers_per_asn'] = numpy.median([len(item) for item in asn_peers])
                        result['mean_peers_per_asn'] = numpy.mean([len(item) for item in asn_peers])

            if e['service_name'] == "virustotal_lookup":
                pdns_a_records = 0
                total_urls = 0
                url_scores = numpy.array([])
                detected_downloaded_scores = numpy.array([])
                detected_communicating_scores = numpy.array([])
                for item in e['results']:
                    if item['subtype'] == "A Records":
                        pdns_a_records += 1
                    if item['subtype'] == "URLs":
                        total_urls += 1
                        if item['total'] != 0:
                            numpy.append(url_scores, float(item["positives"])/float(item['total']))
                        else:
                            numpy.append(url_scores, float(item["positives"])/float(55))

                    if item['subtype'] == "Detected Downloaded Samples":
                        if item['total'] != 0:
                            detected_downloaded_scores = numpy.append(detected_downloaded_scores, float(item["positives"])/float(item['total']))
                        else:
                            detected_downloaded_scores = numpy.append(detected_downloaded_scores, float(item["positives"])/float(55))

                    if item['subtype'] == "Detected Communicating Samples":
                        if item['total'] != 0:
                            detected_communicating_scores = numpy.append(detected_communicating_scores, float(item["positives"])/float(item['total']))
                        else:
                            detected_communicating_scores = numpy.append(detected_communicating_scores, float(item["positives"])/float(55))
                #Need a NAN conversion function. -1 for NAN?
                result['pdns_a_records'] = pdns_a_records
                result['total_urls'] = total_urls
                result['num_url_scores'] = len(url_scores)
                result['num_detected_communicating_scores'] = len(detected_communicating_scores)
                result['num_detected_downloaded_scores'] = len(detected_downloaded_scores)
                result['mean_url_scores'] = numpy.mean(url_scores)
                result['mean_detected_communicating_scores'] = numpy.mean(detected_communicating_scores)
                result['mean_detected_downloaded_scores'] = numpy.mean(detected_downloaded_scores)
                result['median_url_scores'] = numpy.median(url_scores)
                result['median_detected_communicating_scores'] = numpy.median(detected_communicating_scores)
                result['median_detected_downloaded_scores'] = numpy.median(detected_downloaded_scores)
        #print result