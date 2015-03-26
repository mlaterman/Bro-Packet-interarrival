#Track some packet interarrival time information
#Only tracks inbound TCP packets sent from port 80 or 443

@load base/frameworks/sumstats

module P_INTERARRIVAL;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
	ts:	time	&log;
	uid:	string	&log;
	avg:	float	&log;
	dev:	float	&log;
	max:	float	&log;
	min:	float	&log;
    };
    global conn_list: table[string] of time;
}

event bro_init() {
    Log::create_stream(LOG. [$columns=Info]);
    local r1 = SumStats::Reducer($stream="packet arrival", $apply=set(SumStats::AVERAGE, SumStats::STD_DEV, SumStats::MAX, SumStats::MIN));
    SumStats::create([$name = "Packet Interarrival Tracking",
		      $epoch = 1hr,
		      $reducers = set(r1),
		      $epoch_results(ts: time, key: SumStats::Key, results: SumStats::Result) = {
			local l = Info($ts=network_time(), $uid=key$str, $avg=results$average,
				       $dev=results$std_dev, $max=results$max, $min=results$min);
			Log::write(LOG, l);
    }]);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) &priority=-5 {
    if ( ! is_orig && Site::is_local_addr(c$id$orig_h) && ( c$id$resp_p == 80 || c$id$resp_p == 443 ) ) {
	if ( c$uid in conn_list ) {
	    SumStats::observe("packet arrival", [$str=c$uid], [$dbl=|network_time()-conn_list[c$uid]|] );
	}
	conn_list[c$uid] = network_time();
    }
}

event connection_state_remove (c: connection) {
    if ( c$uid in conn_list )
	del conn_list[c$uid];
}
