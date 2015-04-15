// mongo localhost:27017/crits --quiet find_benign_and_malicious_domains.js > out.txt

cursor = db.domains.find( 
{
	$and: [
		{'source.name': 'benign'},
		{'source.name': 'maltrieve'}
	]
}, 
	{
		_id: 0,
		domain: 1
	} 
);

while(cursor.hasNext()) {
	printjsononeline(cursor.next());
}
