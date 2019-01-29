@load /usr/local/lib/bro/plugins/APACHE_KAFKA/scripts

redef Kafka::logs_to_send = set( Notice::LOG );
redef Kafka::topic_name = "cobalt-activity";
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "kafka-broker.example.ex"
);


@load base/frameworks/notice
@load base/protocols/smb

export {
  redef enum Notice::Type += { SMB, NTLM, HTTPS };
  global isTrusted = T;
  global trustedIPs: set[addr] = {} &redef;
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
    isTrusted = hostAdminCheck(c$id$orig_h);
    if (isTrusted == F){
      if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
      {
        NOTICE([$note=SMB, $msg=fmt("Potentially Malicious Use of an Administrative Share"), $sub=fmt("%s",path), $conn=c]);
      }
    }
  }
  event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
  {
    isTrusted = hostAdminCheck(c$id$orig_h);
    if (isTrusted ==F){
      if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
        {
        NOTICE([$note=SMB, $msg=fmt("Potentially Malicious Use of an Administrative Share"), $sub=fmt("%s",path), $conn=c]);
        }
      }
    }
  event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
  {
    local domain = "";
    local user = "";
    local ws = "";
    if (request ?$ user_name)
    {
      user = request$user_name;
    } else {
      NOTICE([$note=NTLM, $msg=fmt("Malicious looking NTLM auth request without user"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
    if (request ?$ domain_name)
    {
      domain = request$domain_name;
    } else {
      NOTICE([$note=NTLM, $msg=fmt("Malicious looking NTLM auth request without domain"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
    if (request ?$ workstation)
    {
      ws = request$workstation;
    } else {
      NOTICE([$note=NTLM, $msg=fmt("Malicious looking NTLM auth request without hostname"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
    
  }
  event ssl_established(c: connection ) &priority=6
  {
  if ( c$ssl ?$ subject)
  {
    if ( c$ssl$subject == "CN=,OU=,O=,L=,ST=,C=" )
      {
      print fmt("subj is \"%s\" on %s", c$ssl$subject, c$id$resp_h);
      NOTICE([$note=HTTPS, $msg=fmt("Malicious looking connection with empty(cobalt?) certificate"), 
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
      NOTICE([$note=SMB, $msg=fmt("Probably malicious svcctl invocation over SMB"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
    if ( c$dce_rpc$endpoint == "IWbemServices" )
    {
      NOTICE([$note=SMB, $msg=fmt("Probably malicious WMI invocation over SMB"), $sub=fmt("%s to %s",c$id$orig_h, c$id$resp_h), $conn=c]);
    }
  }
}

