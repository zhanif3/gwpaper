
cursor = db.analysis_results.find( 
	{
		service_name: "chompy", 
		status: { $in: ["error", "started"]}, 
		analyst: { $in: ["ingest", "maltrieve"]}, 
		results: []
	}, 
	{
		object_id: 1, 
		status: 1, 
		analyst: 1
	} 
);

print(cursor.count())

while(cursor.hasNext()) {
	printjson(cursor.next());
}