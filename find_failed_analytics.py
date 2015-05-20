import sys
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

FMT = '%Y-%m-%d %H:%M:%S.%f'
START_DATE = datetime(2015, 5, 18, 9)
END_DATE = datetime(2015, 5, 19, 9)

client = MongoClient()

db = client['crits']
analysis_results = db['analysis_results']
samples = db['sample']

service_query = {
    "service_name": { "$in": ["virustotal_lookup", "yara", "peinfo"] },
    "status": { "$in": ["started", "error"] },
    "object_type": "Sample"
}

count = {
    "started": 0,
    "error": {
        'vt': 0,
        'yara': 0,
        'peinfo': 0}
}
for analysis in analysis_results.find(service_query):
    sample = samples.find_one( {"_id": ObjectId(analysis["object_id"])} )
    try:
        if sample['source'][0]['name'] == "skald_test":
            date = datetime.strptime(analysis['start_date'], fmt)
            if START_DATE <= date and END_DATE >= date:
                if service['status'] == 'started':
                    count['started'] = count['started'] + 1
                elif analysis["service_name"] == "virustotal_lookup":
                    count['error']['vt'] = count['error']['vt'] + 1
                elif analysis["service_name"] == "yara":
                    count['error']['yara'] = count['error']['yara'] + 1
                elif analysis["service_name"] == "peinfo":
                    count['error']['peinfo'] = count['error']['peinfo'] + 1
                else:
                    print(analysis)

    except:
        print(sys.exc_info())

print(count)