6. Splunk Commands and Functions
Command 	|    Purpose	|      Example
stats	 Aggregate data	                stats count by src_ip

table	Display fields in a table	        table src_ip, dest_ip, action

search	Filter events	                    search "failed login"

rex	    Extract fields with regex	        rex field=url "user=(?<username>\w+)"

eval	Create calculated fields	        eval risk_score = case(severity=="high", 10, severity=="medium", 5)

join	Combine datasets	                join src_ip [search index=threat_intel]

lookup	Enrich data with external tables	lookup threatfeeds   csv src_ip OUTPUT threat_type