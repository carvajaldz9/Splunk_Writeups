| Command        | Purpose                              | Example                                                               |
| -------------- | ------------------------------------ | --------------------------------------------------------------------- |
| `stats`        | Aggregate data                       | `stats count by src_ip`                                               |
| `table`        | Display fields in a table            | `table src_ip, dest_ip, action`                                       |
| `search`       | Filter events                        | `search "failed login"`                                               |
| `rex`          | Extract fields with regex            | `rex field=url "user=(?<username>\\w+)"`                              |
| `eval`         | Create calculated fields             | `eval risk_score = case(severity=="high", 10, severity=="medium", 5)` |
| `join`         | Combine datasets                     | `join src_ip [search index=threat_intel]`                             |
| `lookup`       | Enrich data with external tables     | `lookup threatfeeds.csv src_ip OUTPUT threat_type`                    |
| `where`        | Filter results after transformation  | `where count > 100`                                                   |
| `sort`         | Order results                        | `sort -count`                                                         |
| `top`          | Display most frequent values         | `top user`                                                            |
| `dedup`        | Remove duplicate events              | `dedup user`                                                          |
| `fields`       | Include/exclude fields               | `fields user, src_ip, dest_ip`                                        |
| `rename`       | Rename a field                       | `rename user AS username`                                             |
| `transaction`  | Group related events                 | `transaction user maxspan=5m`                                         |
| `timechart`    | Create time-based charts             | `timechart count by status`                                           |
| `bucket`       | Group time into buckets              | `bucket _time span=1h`                                                |
| `inputlookup`  | Load data from a lookup file         | `inputlookup threatfeeds.csv`                                         |
| `outputlookup` | Save search results to a lookup file | `outputlookup saved_results.csv`                                      |
| `spath`        | Extract fields from JSON             | `spath input=payload output=status path=status_code`                  |
