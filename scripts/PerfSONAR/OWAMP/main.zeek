##! Implements base functionality for OWAMP analysis.
##! Generates the Owamp.log file.

module Owamp;
export {
       redef enum Log::ID += { LOG };
}

module PerfSONAR;

export {
	type owamp_info: record {
		ts:				time &log;
		uid:			string &log;
		id:				conn_id &log;
		server_modes:	count &log;
		client_mode:	count &log;
		keyid:			string &log;
		accept:			bool &log;
		deny_code:		count &log &optional;
	};
}

redef record connection += {
	owamp: owamp_info &optional;
};

function set_session(c: connection)
        {
        if ( ! c?$owamp )
                {
                local info: PerfSONAR::owamp_info;
                info$ts  = network_time();
                info$uid = c$uid;
                info$id  = c$id;

                c$owamp = info;
                }
        }

event zeek_init() &priority=5
	{
	Log::create_stream(Owamp::LOG, [$columns=owamp_info, $path="owamp"]);

	}

event owamp_server_greeting(c: connection, modes: int){
	set_session(c);
	c$owamp$server_modes = int_to_count(modes);
}

event owamp_client_reply(c: connection, modes: int, keyid: string){
	set_session(c);
	c$owamp$client_mode = int_to_count(modes);
	if(keyid != ""){
		c$owamp$keyid = keyid;
	}
}

event owamp_server_accept(c: connection, accept: int){
	if(accept == 0){
		c$owamp$accept = T;
		event owamp_log(c);

	}else{
		c$owamp$accept = F;
		c$owamp$deny_code = int_to_count(accept);

		# go ahead and log, the connection should be dying.
		event owamp_log(c);
	}
}


event owamp_log(c: connection)
	{

	# TODO, we could convert some of these to strings (like modes) for easier reading.
	Log::write(Owamp::LOG, c$owamp);
}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
        {
		if ( atype == Analyzer::ANALYZER_OWAMP )
				if ( info?$c ) {
					set_session(info$c);
                }
        }



