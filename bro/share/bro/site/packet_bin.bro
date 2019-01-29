module PACKET_BIN;

#redef LogAscii::use_json = T;

export {
    redef enum Log::ID += { LOG };
	type Conn2: record {
		orig_h: addr;
		resp_h: addr;
		resp_p: port;
	};
    type Info: record {
		ts: time &log;
		orig_h: addr &log;
		resp_h: addr &log;
		resp_p: string &log;
		intrvl: string &log;
    };

}


global last_conn: table[Conn2] of time;
global interval_hist: table[count] of count;

event bro_init()
{
#    local filter: Log::Filter =
#        [
#        $name="sqlite",
#        $path="./conn.db",
#        $config=table(["tablename"] = "conn"),
#        $writer=Log::WRITER_SQLITE
#        ];
#    
#     Log::add_filter(Conn::LOG, filter);

    print "Starting xs::PACKET_BIN...";
    Log::create_stream(PACKET_BIN::LOG, [$columns=PACKET_BIN::Info, $path="packet_bin"]);
}

event bro_done()
{
    print "xs::PACKET_BIN finished";
}

event new_connection(c: connection) {
	local c2 = Conn2($orig_h = c$id$orig_h, $resp_h = c$id$resp_h, $resp_p = c$id$resp_p);
	#local req: ActiveHTTP::Request = ActiveHTTP::Request($url=url, $max_time=3sec, $addl_curl_args="-k -A dirty-touch-lel");

	if (c2 in last_conn) {

#		when (local resp = ActiveHTTP::request( ActiveHTTP::Request(
#				$url = "http://127.0.0.1:8086/write?db=rxtest", 
#				$method="POST", 
#				$max_time = 5sec, 
#				$addl_curl_args="--data-binary " + fmt("\"INTERVALS,orig_h=%s,resp_h=%s,resp_p=%s value=%0.1f\"", c$id$orig_h, c$id$resp_h, c$id$resp_p, | (c$start_time - last_conn[c2])| ) 
#				)) ) {
#			#print resp;
#		}

		local intrvl: count  =  double_to_count(|(c$start_time - last_conn[c2]) * 2| );  # / 60.0

		if (intrvl !in interval_hist) {
			interval_hist[intrvl] = 0;
		}

		interval_hist[intrvl] += 1;
		if (intrvl >= 1) {
			#print intrvl;
		}
		Log::write( PACKET_BIN::LOG, [ $ts = c$start_time, $orig_h = c$id$orig_h, $resp_h = c$id$resp_h, $resp_p = fmt("%s", c$id$resp_p), $intrvl = fmt("%0.1f", c$start_time - last_conn[c2]) ]);

	} 
	last_conn[c2] = c$start_time;


	#print c2;
}

#Log::write( HTTP_REQS::LOG, [$src = rec$id$orig_h, $ratio = 1.0 * get_count[rec$id$orig_h] / req_count[rec$id$orig_h]]);

