# @TEST-EXEC: zeek -C -r $TRACES/owamp-auth-E.pcap %INPUT
# @TEST-EXEC: zeek-cut server_modes client_mode keyid accept deny_code < owamp.log > owamp.tmp && mv owamp.tmp owamp.log
# @TEST-EXEC: btest-diff owamp.log
