from pymongo import MongoClient
client = MongoClient()

db = client['crits']
services = db['services']
samples = db['sample']

service_query = {
    "service_name": { "$in": ["virustotal_lookup", "yara", "peinfo"] },
    "status": "started"
}
sample_query = {
    "source.name": "skald_test"
}

count = 0
for service in services.find(service_query):
    sample = samples.find( {"_id": service["_id"]} )
    if sample['source.name'] == "skald_test":
        count = count + 1

print(count)