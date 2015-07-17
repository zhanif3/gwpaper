import requests
import json
from pythonwhois import parse 
import numpy
payload = "Domain Name: cncrk.com\nRegistry Domain ID: \nRegistrar WHOIS Server: whois.ename.com\nRegistrar URL: http://www.ename.net\nUpdated Date: 2014-01-04 T01:55:35Z\nCreation Date: 2004-06-16 T09:08:50Z\nRegistrar Registration Expiration Date: 2015-06-16 T09:08:50Z\nRegistrar: eName Technology Co.,Ltd.\nRegistrar IANA ID: 1331\nRegistrar Abuse Contact Email: abuse@ename.com\nRegistrar Abuse Contact Phone: +86.4000044400\nDomain Status: clientDeleteProhibited\nDomain Status: clientTransferProhibited\nDomain Status: clientUpdateProhibited\nRegistry Registrant ID:\nRegistrant Name: Xiamen eName Network Co., Ltd.\nRegistrant Organization: Xiamen eName Network Co., Ltd.\nRegistrant Street: zhen zhu wan ruan jian yuan\nRegistrant City: Xiamenshi\nRegistrant State/Province: Fujian\nRegistrant Postal Code: 361000\nRegistrant Country: CN\nRegistrant Phone: +86.05922669759\nRegistrant Phone Ext: \nRegistrant Fax: +86.05922669760\nRegistrant Fax Ext: \nRegistrant Email: nowy186yo@enamewhois.com\nRegistry Admin ID:\nAdmin Name: Xiamen eName Network Co., Ltd.\nAdmin Organization: Xiamen eName Network Co., Ltd.\nAdmin Street: zhen zhu wan ruan jian yuan\nAdmin City: Xiamenshi\nAdmin State/Province: Fujian\nAdmin Postal Code: 361000\nAdmin Country: CN\nAdmin Phone: +86.05922669759\nAdmin Phone Ext: \nAdmin Fax: +86.05922669760\nAdmin Fax Ext: \nAdmin Email: nowy186yo@enamewhois.com\nRegistry Tech ID:\nTech Name: Xiamen eName Network Co., Ltd.\nTech Organization: Xiamen eName Network Co., Ltd.\nTech Street: zhen zhu wan ruan jian yuan\nTech City: Xiamenshi\nTech State/Province: Fujian\nTech Postal Code: 361000\nTech Country: CN\nTech Phone: +86.05922669759\nTech Phone Ext: \nTech Fax: +86.05922669760\nTech Fax Ext: \nTech Email: nowy186yo@enamewhois.com\nName Server: NS1.DNSV2.COM \nName Server: NS2.DNSV2.COM \nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2015-03-14 T04:50:58Z <<<\n\n"

"""
r = requests.post('http://api.how2doit.de/services/whois/', data=payload)
js = r.json()

print js

admin_contact = js['contacts']['admin']

print admin_contact['city']
print admin_contact['postalcode']
print json.dumps(admin_contact)
"""
def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj

def verify_address(address_dictionary):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.post('http://api.how2doit.de/services/addressverification/', data=json.dumps(address_dictionary, default=date_handler), headers=headers)
    #print address_dictionary
    #print r
    js = r.json()

    return js

def verify_freemail(email):
    if len(email) == 0:
        return {}
    domain = email.split('@')[1]
    if domain == 0:
        return {}
    else:
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get('http://api.how2doit.de/services/freemail/%s/' %(domain), headers=headers)

        try:
            return r.json()
        except Exception as e:
            return {}

def parse_whois(payload):
    try:
        js = parse.parse_raw_whois([payload])
        if 'raw' in js:
            del js['raw']
        return js
    except KeyError:
        print("KEYERROR!")
        return {}
    except ValueError:
        print("VALUEERROR")
        return {}
        
def check_vt_domain(domain):
    vt_api_key = '592d5f6cfb52135f48e9f2a9720631f7e3023efe8bad8b18961fb7af480e76c0'

    # File report
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey': vt_api_key,
          'domain': domain
          }

    response = requests.get(url, params=params)
    print(response.text)
    return response.json()

def check_vt_ip(ipaddr):
    vt_api_key = '592d5f6cfb52135f48e9f2a9720631f7e3023efe8bad8b18961fb7af480e76c0'

    # File report
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': vt_api_key,
          'ip': ipaddr
          }
    response = requests.get(url, params=params)
    return response.json()

if __name__ == '__main__':
    #print len(check_vt_ip('8.8.8.8')['detected_urls']) #['response_code']
    #print numpy.mean(numpy.array([line['positives'] for line in check_vt_domain('google.com')['detected_urls']]))
    print(verify_freemail('zh4990@gmail.com'))
