# @TEST-EXEC: bro -C -r $TRACES/owamp-auth-failed.pcap ../../../scripts %INPUT
# @TEST-EXEC: bro-cut server_modes client_mode keyid accept deny_code < owamp.log > owamp.tmp && mv owamp.tmp owamp.log
# @TEST-EXEC: btest-diff owamp.log
