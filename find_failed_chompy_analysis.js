// mongo localhost:27017/crits --quiet find_failed_chompy_analysis.js > out.txt

cursor = db.analysis_results.find( 
	{
		service_name: "chompy", 
		status: { $in: ["error", "started"]}, 
		analyst: { $in: ["ingest", "maltrieve"]}
	}, 
	{
                _id: 0,
		object_id: 1, 
		status: 1, 
		analyst: 1
	} 
);

while(cursor.hasNext()) {
	printjsononeline(cursor.next());
}
