// ─── Static path arrays (zero runtime cost) ───────────────────────────────────
//
// These cover every field name found across all Wazuh default decoders
// (all 280+ fields used in 2+ decoder files, sourced from
//  /var/ossec/ruleset/decoders + /var/ossec/etc/decoders).

pub(crate) const SRC_IP: &[&str] = &[
    // Generic syslog / OSSEC (256 decoders use srcip)
    "srcip", "src_ip", "source_ip", "source_address", "sourceip", "sourceIpAddress",
    "src", "ip", "host_ip", "ip_address", "proxy_ip", "xff_address",
    // Lowercase variants seen across miscellaneous decoders
    "locip",         // pfSense/ipfw: local (source) IP
    "ipaddr",        // DHCP / keepalived
    "ip.address",    // dot-notation nested field
    "LocalIp",       // Prelude/OSSIM sensor format
    "identSrc",      // Prelude correlation source
    "assignip",      // DHCP lease assignment
    "client_dyn_ip", // dynamic-IP allocation logs
    // Suricata / Snort
    "alert.src_ip",
    // Windows Event Channel
    "win.eventdata.ipAddress", "win.eventdata.sourceAddress", "win.eventdata.IpAddress",
    // AWS CloudTrail / GuardDuty
    "aws.sourceIPAddress", "aws.requestParameters.ipAddress",
    // AWS GuardDuty — network connection & port probe (deep nested)
    "aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4",
    "aws.service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4",
    // AWS VPC Flow Logs (Wazuh aws-vpcflow decoder)
    "srcAddr",
    // GCP Audit
    "gcp.protoPayload.requestMetadata.callerIp",
    // Azure AD / Azure Monitor
    "azure.callerIpAddress",
    "azure.properties.ipAddress",
    "azure.properties.clientIP",
    // Okta System Log
    "okta.client.ipAddress",
    // Office365
    "office365.ActorIpAddress", "office365.ClientIP",
    // GitHub audit
    "github.actor_ip",
    // Zeek/Bro network sensor
    "zeek.id.orig_h",
    // VPN / IPSec / proxy
    "remip",           // remote peer IP in IPSec/VPN tunnels
    "tunnelip",        // tunnel source endpoint IP
    "forwardedfor",    // HTTP X-Forwarded-For (original client behind proxy)
    "x_forwarded_for", // underscore variant of X-Forwarded-For
    // CEF / ArcSight fields
    "cs1",
];

pub(crate) const DST_IP: &[&str] = &[
    "dstip", "dst_ip", "dest_ip", "destination_ip", "destip", "dstname",
    "destinationIpAddress", "destination_address",
    "dst",
    "dstcip",  // Cisco ASA: destination translated IP
    "dhost",   // CEF/ArcSight destination host (IP)
    "alert.dest_ip",
    "win.eventdata.destinationIp", "win.eventdata.DestinationIp",
    // AWS VPC Flow Logs
    "dstAddr",
    // AWS GuardDuty — local (victim) IP
    "aws.service.action.networkConnectionAction.localIpDetails.ipAddressV4",
    // Zeek/Bro network sensor
    "zeek.id.resp_h",
];

pub(crate) const SRC_PORT: &[&str] = &[
    "srcport", "src_port", "source_port",
    "locport",   // pfSense/ipfw: local (source) port
    "LocalPort", // Prelude sensor format
    "s_port",    // some syslog decoders
    "spt",       // CEF Source Port
    "sport",     // generic source port alias (haproxy, misc)
    "alert.src_port",
    "win.eventdata.ipPort", "win.eventdata.IpPort",
    "cs2",
    // AWS VPC Flow Logs
    "srcPort",
    // AWS GuardDuty — remote (attacker) port
    "aws.service.action.networkConnectionAction.remotePortDetails.port",
    // Zeek/Bro network sensor originator port
    "zeek.id.orig_p",
];

pub(crate) const DST_PORT: &[&str] = &[
    "dstport", "dst_port", "dest_port", "destination_port",
    "remport", // pfSense/ipfw: remote (destination) port
    "dpt",     // CEF Destination Port
    "dport",   // generic destination port alias (haproxy, misc)
    "alert.dest_port",
    "win.eventdata.destinationPort", "win.eventdata.DestinationPort",
    // AWS VPC Flow Logs
    "dstPort",
    // AWS GuardDuty — local (victim) port
    "aws.service.action.networkConnectionAction.localPortDetails.port",
    // Zeek/Bro network sensor responder port
    "zeek.id.resp_p",
];

pub(crate) const NAT_SRC_IP: &[&str] = &[
    "nat_srcip", "nat_src_ip", "nat_source_ip",
    // FortiGate: source NAT translated IP
    "transip",
    // PAN-OS
    "mapped_src_ip",
    // Check Point / Juniper: translated source IP
    "xlatesrc",
    // Cisco ASA / generic
    "tran_src_ip",
];

pub(crate) const NAT_DST_IP: &[&str] = &[
    "nat_dstip", "nat_dst_ip", "nat_destination_ip",
    "nat_dest_ip", "mapped_dst_ip",
    "xlatedst",    // Check Point / Juniper: translated destination IP
    "tran_dst_ip", // Cisco ASA / generic
];

pub(crate) const NAT_SRC_PORT: &[&str] = &[
    "nat_srcport", "nat_src_port", "nat_source_port",
    // FortiGate: translated source port
    "transport",
    "mapped_src_port",
    "xlatesport",    // Check Point / Juniper: translated source port
    "tran_src_port", // Cisco ASA / generic
];

pub(crate) const NAT_DST_PORT: &[&str] = &[
    "nat_dstport", "nat_dst_port", "nat_destination_port",
    "nat_dest_port", "mapped_dst_port",
    "xlatedport",    // Check Point / Juniper: translated destination port
    "tran_dst_port", // Cisco ASA / generic
];

pub(crate) const PROTOCOL: &[&str] = &[
    "protocol", "proto", "transport", "protocol_id",
    "Protocol",         // uppercase variant (some vendor decoders)
    "ip_protocol",      // IP protocol number (auditd, netfilter)
    "alert.proto",
    "win.eventdata.protocol",
    "network_forwarded_protocol",
];

pub(crate) const BYTES_IN: &[&str] = &[
    // FortiGate
    "rcvdbyte",
    // generic
    "bytes_recv", "bytes_in", "bytesIn", "bytes",
    // Case variants / other vendors
    "BytesReceived",     // Check Point / Cylance
    "bytes_received",    // pfSense / generic
    "bytes_from_server", // proxy / WAF logs (server → client = inbound)
    // AWS CloudTrail S3 / Transfer data events
    "aws.additionalEventData.bytesTransferredIn",
    // AWS VPC Flow — total bytes for the flow
    "aws.bytes",
];

pub(crate) const BYTES_OUT: &[&str] = &[
    // FortiGate
    "sentbyte",
    // generic
    "bytes_sent", "bytes_out", "bytesOut",
    // Case variants / other vendors
    "BytesSent",         // Check Point / Cylance
    "bytes_from_client", // proxy / WAF logs (client → server = outbound)
    // AWS CloudTrail S3 / Transfer data events
    "aws.additionalEventData.bytesTransferredOut",
];

pub(crate) const ACTOR_USER: &[&str] = &[
    // Generic (80 decoders use user/srcuser/username)
    "srcuser", "src_user", "user", "username", "user_name", "source_user",
    "userName", "userAccount",
    "userid", "userID",      // lowercase / camelCase user-id variants
    "LoggedUser",            // Check Point / Prelude: currently-logged-in user
    "SourceUserName",        // Check Point R80 field name
    "client_user",           // proxy / squid decoders
    "database_user",         // MySQL / PostgreSQL audit
    "ldap_data.Username",    // OpenLDAP decoder
    // auditd
    "audit.acct", "audit.auid",
    // Common authlog / syslog user fields
    "login",         // generic login name (sshd, PAM, ftpd)
    "logname",       // syslog logname field (su, sudo)
    "usrName",       // ArcSight / LEEF alternate casing
    "xauthuser",     // VPN XAUTH / L2TP authenticated user
    "account_name",  // Windows/LDAP account name
    "subject.account_name", // Windows Security subject account (nested)
    // Windows — subject (the initiating service/process) or target account.
    "win.eventdata.subjectUserName", "win.eventdata.SubjectUserName",
    "win.eventdata.targetUserName",  "win.eventdata.TargetUserName",
    "win.eventdata.initiatorAccountName",
    // AWS
    "aws.userIdentity.userName", "aws.userIdentity.principalId",
    "aws.userIdentity.sessionContext.sessionIssuer.userName",
    // GCP
    "gcp.protoPayload.authenticationInfo.principalEmail",
    // Azure AD / Azure Monitor sign-in logs
    "azure.properties.userPrincipalName",
    "azure.properties.initiatedBy.user.userPrincipalName",
    // Okta System Log — email-based actor identity
    "okta.actor.alternateId",
    "okta.actor.displayName",
    // Office365
    "office365.UserId",
    // GitHub
    "github.actor",
    // MariaDB/MySQL
    "mariadb.username",
    // ArcSight / CEF
    "cs5",
];

pub(crate) const TARGET_USER: &[&str] = &[
    "dstuser", "dst_user", "target_user", "destination_user",
    "TargetUserName", // Check Point R80 / Windows camelCase variant
    "new_user",       // useradd / adduser decoders: the account being created
    "removed_user",   // userdel / account-removal decoders: account being deleted
    "win.eventdata.targetUserName", "win.eventdata.TargetUserName",
    "win.system.security.userID",
];

pub(crate) const DOMAIN: &[&str] = &[
    "domain",
    "account_domain",        // Windows NTLM / LDAP domain name
    "dntdom",                // CEF destination NT domain name
    "subject.account_domain", // Windows Security subject domain (nested)
    "win.eventdata.subjectDomainName", "win.eventdata.SubjectDomainName",
    "win.eventdata.targetDomainName",  "win.eventdata.TargetDomainName",
    "aws.userIdentity.accountId",
    // Azure tenant
    "azure.tenantId",
    // GCP project
    "gcp.resource.labels.project_id",
    // GitHub organisation
    "github.org",
];

pub(crate) const URL: &[&str] = &[
    "url", "uri", "request_uri",
    "URL", // uppercase variant (some CEF / HP ArcSight decoders)
    "win.eventdata.objectName",
    "aws.requestParameters.url",
    // AWS S3 — bucket name / key being accessed
    "aws.requestParameters.bucketName",
    "gcp.protoPayload.resourceName",
    "github.repo",
    "office365.ObjectId",
    // Azure — resource URI
    "azure.properties.resourceUri",
    // Okta — target resource display name
    "okta.target.displayName",
];

pub(crate) const HTTP_METHOD: &[&str] = &[
    "method", "http_method", "reqtype",
    "aws.requestParameters.httpMethod",
];

pub(crate) const HTTP_STATUS: &[&str] = &[
    "http_response_code", "http_status_code", "http_status",
    "response_code", "status_code",
];

pub(crate) const APP_NAME: &[&str] = &[
    "app", "application", "appName",
    "service", "service_name",
    "product_name",  // generic product/software name (many vendors)
    "product",       // compact product field
    "protocol",      // some decoders re-use protocol as app
    // AWS CloudTrail — which AWS service was called (e.g. "ec2.amazonaws.com")
    "aws.eventSource",
    // Azure — resource/service type
    "azure.resourceType",
    "azure.properties.appDisplayName",
    // Okta — client application / browser
    "okta.target.alternateId",
    "okta.client.userAgent.browser",
];

pub(crate) const FILE_NAME: &[&str] = &[
    "filename", "file_id",
    "sysmon.targetfilename",
    "audit.file.name",
    "TargetPath",
    "TargetFileName",           // Check Point / Windows Sysmon (target of file op)
    "SourceFilePath",           // Check Point: source file full path
    "ChildPath",                // sysmon process-create: child executable path
    "ParentPath",               // sysmon process-create: parent executable path
    // Windows Defender / Microsoft Security
    "win.eventdata.objectName",
    "defender.path",            // Defender threat path
    "defender.pathfound",       // Defender scan hit
    // Antivirus / Cylance / EDR
    "virus", "defender.name",
    "cylance_threats.file_name", "cylance_threats.file_path",
    "cylance_events.filepath",  // Cylance event filepath
    "infected_file_path",       // generic AV alert field
    "target_file",              // target file in various decoders
    "path",                     // generic path field (syslog, Linux)
    "Path",                     // uppercase variant (CEF / Windows)
    "sysmon.imageLoaded",       // Sysmon event 7: DLL/image being loaded
];

pub(crate) const PROCESS_NAME: &[&str] = &[
    "sysmon.image", "sysmon.Image",
    "audit.exe", "audit.command",
    "command", "program", "process",
    "SourceProcessName",  // Check Point / Cylance: initiating process
    "ChildProcessName",   // parent-process audit records
    "defender.processname",
    "process.name",        // dot-notation process name (various)
    "sysmon.commandLine",  // Sysmon Command Line (full invocation string)
    "sysmon.targetImage",  // Sysmon Event 8/10: target process image
    "sysmon.parentImage",  // Sysmon parent process image path
    "sysmon.sourceImage",  // Sysmon source process (thread injection etc.)
    "win.eventdata.image", "win.eventdata.Image",
    "win.eventdata.ProcessName",
];

pub(crate) const PROCESS_ID: &[&str] = &[
    "sysmon.processId", "sysmon.ProcessId",
    "sysmon.processid",  // Sysmon lowercase variant (older Wazuh agents)
    "audit.pid",
    "pid",               // generic lowercase PID (netstat, auditd, misc)
    "PID",               // uppercase PID (Check Point, Cylance LEEF)
    "process.pid",       // dot-notation PID (docker, nested decoders)
    "win.eventdata.processId", "win.eventdata.ProcessId",
    "win.system.execution.processId",
];

pub(crate) const RULE_NAME: &[&str] = &[
    "rule_name", "attack.name", "attack",
    "sysmon.signature",
    "sysmon.ruleName",    // Sysmon v15+ matching rule name
    "signature",
    "ThreatName",         // Cylance / CrowdStrike threat name
    "AnalyzerRuleName",   // Prelude IDMEF analyzer rule name
];

pub(crate) const CATEGORY: &[&str] = &[
    "category", "cat", "appcat", "application_category",
    // PAN-OS / FortiGate
    "subtype", "sub_cat",
    // Windows / CEF
    "Category",
    // EDR / AV threat category
    "ThreatCategory",  // Cylance threat category field
    "threat_category", // generic threat category (Trend, Sophos, etc.)
];

pub(crate) const IFACE_IN: &[&str] = &[
    "srcintf", "inbound_interface", "interface",
    "packet_incoming_interface",
    "source_zone", "srczone",  // zone-based firewall ingress zone
    "in_interface",            // generic inbound interface
    "inzone",                  // FortiGate ingress zone
    "ifname",  "if_name",     // interface name (pfSense, Linux)
    // AWS VPC Flow — ENI that captured the traffic
    "interfaceId",
    // Zeek/Bro — log path indicates sensor/interface (e.g. "conn", "dns")
    "zeek._path",
];

pub(crate) const IFACE_OUT: &[&str] = &[
    "dstintf", "outbound_interface",
    "destination_zone", "dstzone",   // zone-based firewall egress zone
    "out_interface",                  // generic outbound interface
    "outzone",                        // FortiGate egress zone
    "outintf",                        // compact outbound interface name
    "dstinterface",                   // FortiGate destination interface
];

pub(crate) const SRC_HOSTNAME: &[&str] = &[
    "hostname", "srchost", "src_host", "sourceHostname", "source_hostname",
    "dvchost",
    "host",            // generic syslog hostname
    "HostName",        // Prelude / Check Point PascalCase variant
    "AnalyzerHostName",// Prelude IDMEF analyzer host
    "TargetHostName",  // Check Point target device hostname
    "identHostName",   // ident/IDMEF source hostname
    "win.system.computer", "win.eventdata.workstationName",
    "win.eventdata.WorkstationName",
    "srcname",        // source name / hostname (LEEF, ArcSight)
    "sname",          // compact source name (some LEEF decoders)
    "caller_computer", // Windows Security logon: caller computer name
    "machine_name",   // generic machine name
    "machinename",    // no-underscore variant
];

pub(crate) const DST_HOSTNAME: &[&str] = &[
    "dsthost", "dst_host", "destinationHostname", "destination_hostname",
    "sysmon.destinationHostname", // Sysmon Event 3: network connection dest host
    "server_name",               // HTTP SNI / TLS server name
];

pub(crate) const ACTION: &[&str] = &[
    "action", "log_action",
    "Action",             // Check Point / Prelude: PascalCase variant
    "ThreatActionTaken",  // Cylance / CrowdStrike EDR response action
    "RegAction",          // registry hive audit action (create/modify/delete)
    "data.action",        // nested data.action from some syslog decoders
    "alert.action",
    "fw_action",
    "act",                // CEF
    "aws.eventName",
    "gcp.protoPayload.methodName",
    // Azure AD / Monitor — the operation performed
    "azure.operationName",
    "azure.properties.operationType",
    // Okta System Log — human-readable event description and type
    "okta.displayMessage",
    "okta.eventType",
    "github.action",
    "office365.Operation",
    "defender.action",    // Windows Defender quarantine / block / allow
    "operation",          // generic operation name (MariaDB, Check Point, OSSIM)
    "rule_action",        // action from the matching rule (Suricata, Snort)
    "utmaction",          // FortiGate UTM action
];

pub(crate) const STATUS: &[&str] = &[
    "status", "result", "outcome",
    "data.status",               // nested data.status from generic decoders
    "cylance_events.eventstatus", // Cylance event status
    "win.eventdata.status",  "win.eventdata.Status",
    "win.eventdata.failureReason",
    "aws.errorCode",
    // Okta outcome — SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, UNKNOWN
    "okta.outcome.result",
    // Azure AD — "0" = success, non-zero string = error code
    "azure.resultType",
    "azure.resultDescription",
    "audit.res",
    "audit.success",   // auditd success field ("yes"/"no" or "1"/"0")
];
