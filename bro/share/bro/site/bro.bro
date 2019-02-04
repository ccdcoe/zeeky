@load /usr/local/lib/bro/plugins/APACHE_KAFKA/scripts

redef Kafka::logs_to_send = set( Notice::LOG );
redef Kafka::topic_name = "cobalt-activity";
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "kafka-broker.example.ex"
);


@load base/frameworks/notice
@load base/protocols/smb

export {
  const write_cmds: set[string] = {
	"WRITE"
  };

  redef enum Notice::Type += { ZEEK::SMB, ZEEK::NTLM, ZEEK::HTTPS };
  global isTrusted = T;
  global trustedIPs: set[addr] = {} &redef;
  const ignored_command_statuses: set[string] = {
          "MORE_PROCESSING_REQUIRED",
  };

  function hostAdminCheck(sourceip: addr): bool
  {
    if (sourceip !in trustedIPs)
    {
      return F;
    }
    else
    {
      return T;
    }
  }
  
  event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
  {
    if( !Site::is_private_addr(c$id$resp_h)){
      isTrusted = hostAdminCheck(c$id$orig_h);
      if (isTrusted == F){
        if ( "ADMIN$" in path )
        {
          NOTICE([$note=ZEEK::SMB, $msg=fmt("Potentially Malicious Use of an Administrative Share"), $sub=fmt("%s",path), $conn=c]);
        }
      }
		}
  }
  event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
  {
    if( !Site::is_private_addr(c$id$resp_h)){
      isTrusted = hostAdminCheck(c$id$orig_h);
      if (isTrusted ==F){
        if ( "ADMIN$" in path )
          {
          NOTICE([$note=ZEEK::SMB, $msg=fmt("Potentially Malicious Use of an Administrative Share"), $sub=fmt("%s",path), $conn=c]);
          }
        }
			}
    }
  event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
  {
    local domain = "";
    local user = "";
    local ws = "";
    local key = "";
    if (request ?$ session_key)
    {
      key = request$session_key;
    } else {
      NOTICE([$note=ZEEK::NTLM, $msg=fmt("Malicious looking NTLM auth request without session key, probable PTH"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
  }
  event ssl_established(c: connection ) &priority=6
  {
  if ( c$ssl ?$ subject)
  {
    if ( c$ssl$subject == "CN=,OU=,O=,L=,ST=,C=" )
      {
      NOTICE([$note=ZEEK::HTTPS, $msg=fmt("Malicious looking connection with empty(cobalt?) certificate"), 
      $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), 
      $conn=c, 
      $identifier=cat(c$id$orig_h,c$id$resp_h),
      $suppress_for=1min]);
      } 
  }
  }
  event dce_rpc_bind (c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
  {
    local operation = "";
    if (c$dce_rpc ?$ operation)
    {
      operation = c$dce_rpc$operation;
    }
    if ( c$dce_rpc$endpoint == "svcctl" )
    {
      NOTICE([$note=ZEEK::SMB, $msg=fmt("Probably malicious svcctl invocation over SMB"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
    if ( c$dce_rpc$endpoint == "IWbemServices" )
    {
      NOTICE([$note=ZEEK::SMB, $msg=fmt("Probably malicious WMI invocation over SMB"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
  }
  event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
  {	
    if ( is_orig )
      return;
    if ( c$smb_state$current_cmd$status in ignored_command_statuses )
      return;
    if ( c$smb_state$current_cmd$command in write_cmds ){
      SumStats::observe("smb writes", [$str=cat(c$id$orig_h,",",c$id$resp_h)], [$num=1]);
    }
  }
  event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-5
  {	
    if ( is_orig )
      return;
    if ( c$smb_state$current_cmd$status in ignored_command_statuses )
      return;
    if ( c$smb_state$current_cmd$command in write_cmds ){
      SumStats::observe("smb writes", [$str=cat(c$id$orig_h,",",c$id$resp_h)], [$num=1]);
    }
  }
}

event bro_init() &priority=5
{
  local r1: SumStats::Reducer = [$stream="smb writes", $apply=set(SumStats::SUM)];
  SumStats::create([$name="smb writes",
      $epoch=5min,
      $reducers=set(r1),
      $threshold_series=vector( 67.0, 100.0, 300.0 ),
      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
      {
        return result["smb writes"]$sum;
      },
      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
      {
        local r = result["smb writes"];
        local hosts = split_string(key$str, /,/);
          NOTICE([$note=ZEEK::SMB, 
                  $id=[$orig_h=to_addr(hosts[0]),$orig_p=to_port("0/tcp"),
                  $resp_h=to_addr(hosts[1]),$resp_p=to_port("0/tcp")],
                  $msg=fmt("Impressive amount (%s) of SMB_WRITEs detected", r$sum), 
                  $sub=fmt("%s to %s", hosts[0], hosts[1]), 
                  $identifier=cat(key$str)]);
      }]);

}

