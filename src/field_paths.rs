// ─── Static path arrays (zero runtime cost) ───────────────────────────────────
//
// These cover every field name found across all Wazuh default decoders
// (all 280+ fields used in 2+ decoder files, sourced from
//  /var/ossec/ruleset/decoders + /var/ossec/etc/decoders).

pub(crate) const SRC_IP: &[&str] = &[
    // Generic syslog / OSSEC (256 decoders use srcip)
    "srcip",
    "src_ip",
    "source_ip",
    "source_address",
    "sourceip",
    "sourceIpAddress",
    "src",
    "ip",
    "IP",     // uppercase IP variant (some vendor decoders)
    "client", // squid/proxy/proftpd: client = connecting source
    "host_ip",
    "ip_address",
    "proxy_ip",
    "xff_address",
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
    "win.eventdata.ipAddress",
    "win.eventdata.sourceAddress",
    "win.eventdata.IpAddress",
    // AWS CloudTrail / GuardDuty
    "aws.sourceIPAddress",
    "aws.requestParameters.ipAddress",
    "aws.source_ip_address", // snake_case variant from Wazuh aws-cloudtrail decoder
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
    // Office365 — multiple IP field names across workloads (ClientIP = Exchange, ActorIpAddress = SharePoint/AzureAD)
    "office365.ActorIpAddress",
    "office365.ClientIP",
    "office365.ClientIPAddress",
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
    // AWS VPC Flow Logs — source address (lowercase from Wazuh csv decoder)
    "aws.srcaddr",
    // AWS WAF / ALB — client IP inside httpRequest block
    "aws.httpRequest.clientIp",
    // AWS S3 Server Access Logs — remote (client) IP
    "aws.remote_ip",
    // AWS Macie — flagged source IP from summary block
    "aws.summary.IP",
    // GCP DNS Cloud Logging — source IP from jsonPayload
    "gcp.jsonPayload.sourceIP",
    // Amazon Security Lake (OCSF-native relay format uses src_endpoint.*)
    "src_endpoint.ip",
    // Threat intelligence / IOC rules — known botnet/malicious source IP
    "botnetip",
    // Windows Event Channel — lowercase 'Ip' variant used in some Event IDs
    // (different casing from win.eventdata.sourceAddress already above)
    "win.eventdata.sourceIp",
    // MariaDB/MySQL — client connection IP
    "mariadb.ip",
    // Generic forwarded IP (X-Forwarded-For extracted by proxy/LB decoders)
    "forwarded_ip",
    // CEF multi-hop forwarded IP (first hop)
    "network.forwarded_ip_1",
];

pub(crate) const DST_IP: &[&str] = &[
    "dstip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "destip",
    "dstname",
    "destinationIpAddress",
    "destination_address",
    "dst",
    "dstcip", // Cisco ASA: destination translated IP
    "dhost",  // CEF/ArcSight destination host (IP)
    "alert.dest_ip",
    "win.eventdata.destinationIp",
    "win.eventdata.DestinationIp",
    // AWS VPC Flow Logs
    "dstAddr",
    // AWS GuardDuty — local (victim) IP
    "aws.service.action.networkConnectionAction.localIpDetails.ipAddressV4",
    // Zeek/Bro network sensor
    "zeek.id.resp_h",
    // AWS VPC Flow Logs — destination address (lowercase)
    "aws.dstaddr",
    // Qualys Guard — scanned target host IP
    "qualysguard.ip",
];

pub(crate) const SRC_PORT: &[&str] = &[
    "srcport",
    "src_port",
    "source_port",
    "locport",   // pfSense/ipfw: local (source) port
    "LocalPort", // Prelude sensor format
    "s_port",    // some syslog decoders
    "spt",       // CEF Source Port
    "sport",     // generic source port alias (haproxy, misc)
    "alert.src_port",
    "win.eventdata.ipPort",
    "win.eventdata.IpPort",
    "cs2",
    // AWS VPC Flow Logs
    "srcPort",
    // AWS GuardDuty — remote (attacker) port
    "aws.service.action.networkConnectionAction.remotePortDetails.port",
    // Zeek/Bro network sensor originator port
    "zeek.id.orig_p",
    // AWS VPC Flow Logs — source port (lowercase from Wazuh csv decoder)
    "aws.srcport",
    // Amazon Security Lake (OCSF-native relay format)
    "src_endpoint.port",
];

pub(crate) const DST_PORT: &[&str] = &[
    "dstport",
    "dst_port",
    "dest_port",
    "destination_port",
    "remport", // pfSense/ipfw: remote (destination) port
    "dpt",     // CEF Destination Port
    "dport",   // generic destination port alias (haproxy, misc)
    "alert.dest_port",
    "win.eventdata.destinationPort",
    "win.eventdata.DestinationPort",
    // AWS VPC Flow Logs
    "dstPort",
    // AWS GuardDuty — local (victim) port
    "aws.service.action.networkConnectionAction.localPortDetails.port",
    // Zeek/Bro network sensor responder port
    "zeek.id.resp_p",
    // AWS VPC Flow Logs — destination port (lowercase from Wazuh csv decoder)
    "aws.dstport",
    // Amazon Security Lake (OCSF-native relay format)
    "dst_endpoint.port",
];

pub(crate) const NAT_SRC_IP: &[&str] = &[
    "nat_srcip",
    "nat_src_ip",
    "nat_source_ip",
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
    "nat_dstip",
    "nat_dst_ip",
    "nat_destination_ip",
    "nat_dest_ip",
    "mapped_dst_ip",
    "xlatedst",    // Check Point / Juniper: translated destination IP
    "tran_dst_ip", // Cisco ASA / generic
];

pub(crate) const NAT_SRC_PORT: &[&str] = &[
    "nat_srcport",
    "nat_src_port",
    "nat_source_port",
    // FortiGate: translated source port
    "transport",
    "mapped_src_port",
    "xlatesport",    // Check Point / Juniper: translated source port
    "tran_src_port", // Cisco ASA / generic
];

pub(crate) const NAT_DST_PORT: &[&str] = &[
    "nat_dstport",
    "nat_dst_port",
    "nat_destination_port",
    "nat_dest_port",
    "mapped_dst_port",
    "xlatedport",    // Check Point / Juniper: translated destination port
    "tran_dst_port", // Cisco ASA / generic
];

pub(crate) const PROTOCOL: &[&str] = &[
    "protocol",
    "proto",
    "transport",
    "protocol_id",
    "Protocol",    // uppercase variant (some vendor decoders)
    "ip_protocol", // IP protocol number (auditd, netfilter)
    "alert.proto",
    "win.eventdata.protocol",
    "network_forwarded_protocol",
    // AWS VPC Flow Logs — IP protocol number/name (nested under aws.*)
    "aws.protocol",
    // Explicit protocol name field (SentinelOne, some router/SD-WAN decoders)
    "protocol_name",
];

pub(crate) const BYTES_IN: &[&str] = &[
    // FortiGate
    "rcvdbyte",
    // generic
    "bytes_recv",
    "bytes_in",
    "bytesIn",
    "bytes",
    // Case variants / other vendors
    "BytesReceived",     // Check Point / Cylance
    "bytes_received",    // pfSense / generic
    "bytes_from_server", // proxy / WAF logs (server → client = inbound)
    // AWS CloudTrail S3 / Transfer data events
    "aws.additionalEventData.bytesTransferredIn",
    // AWS VPC Flow — total bytes for the flow
    "aws.bytes",
    "recv_bytes", // generic received bytes (some syslog decoders)
];

pub(crate) const BYTES_OUT: &[&str] = &[
    // FortiGate
    "sentbyte",
    // generic
    "bytes_sent",
    "bytes_out",
    "bytesOut",
    "sent_bytes", // explicit variant (some syslog decoders)
    // Case variants / other vendors
    "BytesSent",         // Check Point / Cylance
    "bytes_from_client", // proxy / WAF logs (client → server = outbound)
    // AWS CloudTrail S3 / Transfer data events
    "aws.additionalEventData.bytesTransferredOut",
];

pub(crate) const ACTOR_USER: &[&str] = &[
    // Generic (80 decoders use user/srcuser/username)
    "srcuser",
    "src_user",
    "user",
    "username",
    "user_name",
    "source_user",
    "account", // generic account field
    "admin",   // admin username field (some management decoders)
    "userName",
    "userAccount",
    "userid",
    "userID",             // lowercase / camelCase user-id variants
    "LoggedUser",         // Check Point / Prelude: currently-logged-in user
    "SourceUserName",     // Check Point R80 field name
    "client_user",        // proxy / squid decoders
    "database_user",      // MySQL / PostgreSQL audit
    "ldap_data.Username", // OpenLDAP decoder
    // auditd
    "audit.acct",
    "audit.auid",
    // Common authlog / syslog user fields
    "login",                // generic login name (sshd, PAM, ftpd)
    "logname",              // syslog logname field (su, sudo)
    "usrName",              // ArcSight / LEEF alternate casing
    "xauthuser",            // VPN XAUTH / L2TP authenticated user
    "account_name",         // Windows/LDAP account name
    "subject.account_name", // Windows Security subject account (nested)
    // Windows — subject (the initiating service/process) or target account.
    "win.eventdata.subjectUserName",
    "win.eventdata.SubjectUserName",
    "win.eventdata.targetUserName",
    "win.eventdata.TargetUserName",
    "win.eventdata.initiatorAccountName",
    // AWS
    "aws.userIdentity.userName",
    "aws.userIdentity.principalId",
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
    // AWS S3 Server Access Logs — IAM requester (ARN or AWS service)
    "aws.requester",
    // AWS CloudTrail / KMS — username for human IAM Identity users
    "aws.userIdentity.userName",
    // AWS CloudTrail — full ARN fallback when userName is absent (assumed-role, service accounts)
    "aws.userIdentity.arn",
    // Office365 — UserKey is a stable per-user GUID (used when UserId is a SID)
    "office365.UserKey",
    // GitHub
    "github.actor",
    // MariaDB/MySQL
    "mariadb.username",
    // ArcSight / CEF
    "cs5",
    // CEF Source User Name (suser) — used in ArcSight, Barracuda, F5 BigIP, etc.
    "suser",
    // SentinelOne / generic EDR source user name (PascalCase variant)
    "sourceUserName",
    // Amazon Security Lake OCSF-native format
    "identity.user.name",
    // Office365 — actor field (alternate to UserId, captures display name in some workloads)
    "office365.actor",
    // Windows Security — SAM account name of the subject (initiating account)
    "win.eventdata.subjectAccountName",
];

pub(crate) const TARGET_USER: &[&str] = &[
    "dstuser",
    "dst_user",
    "target_user",
    "destination_user",
    "TargetUserName", // Check Point R80 / Windows camelCase variant
    "new_user",       // useradd / adduser decoders: the account being created
    "removed_user",   // userdel / account-removal decoders: account being deleted
    "win.eventdata.targetUserName",
    "win.eventdata.TargetUserName",
    "win.system.security.userID",
    // Windows Security — target account SID (for account-change and privilege events)
    "win.eventdata.targetUserSid",
    "win.eventdata.targetSid",
];

pub(crate) const DOMAIN: &[&str] = &[
    "domain",
    "account_domain",         // Windows NTLM / LDAP domain name
    "dntdom",                 // CEF destination NT domain name
    "subject.account_domain", // Windows Security subject domain (nested)
    "win.eventdata.subjectDomainName",
    "win.eventdata.SubjectDomainName",
    "win.eventdata.targetDomainName",
    "win.eventdata.TargetDomainName",
    "aws.userIdentity.accountId",
    // AWS CloudTrail — account ID in a different field for cross-account events
    "aws.recipientAccountId",
    // AWS CloudTrail — region (maps to cloud.region in OCSF; closest we have is domain)
    "aws.awsRegion",
    // Office365 — organisation/tenant UUID (cloud.account_uid equivalent)
    "office365.OrganizationId",
    // Azure tenant
    "azure.tenantId",
    // GCP project
    "gcp.resource.labels.project_id",
    // GitHub organisation
    "github.org",
    // Database name used as organisational domain for DB audit sources
    "mariadb.database",
    "mongodb.database",
    "sqlserver.dbname",
    // GCP — bucket name is the resource/organisational boundary for storage events
    "gcp.bucket",
    // GitLab — project path acts as FQDN-like domain for repo events
    "project_path",
];

pub(crate) const URL: &[&str] = &[
    "url",
    "uri",
    "request_uri",
    "URL", // uppercase variant (some CEF / HP ArcSight decoders)
    "win.eventdata.objectName",
    "aws.requestParameters.url",
    "request", // HTTP request line / path (web access log decoders)
    // AWS S3 — bucket name / key being accessed
    "aws.requestParameters.bucketName",
    "gcp.protoPayload.resourceName",
    "github.repo",
    "office365.ObjectId",
    // Office365 SharePoint / OneDrive — full URL of the affected resource
    "office365.SiteUrl",
    // Office365 SharePoint — relative path of the source file
    "office365.SourceRelativeUrl",
    // Azure — resource URI
    "azure.properties.resourceUri",
    // Okta — target resource display name
    "okta.target.displayName",
    // AWS S3 Server Access Logs — full request URI (e.g. /bucket/key?param=val)
    "aws.request_uri",
    // AWS WAF — URI from httpRequest block
    "aws.httpRequest.uri",
    // Cloudflare WAF — full client request URI
    "ClientRequestURI",
    // Windows Event Channel — SMB/network share name (file share access events)
    "win.eventdata.shareName",
    // Windows Sysmon — registry key or file target (Event ID 13/14 registry set)
    "win.eventdata.targetObject",
    // URL path component extracted by some proxy/WAF decoders
    "url_path",
    // DNS / SQL / HTTP query string used as resource identifier by some decoders
    "query_string",
];

pub(crate) const HTTP_METHOD: &[&str] = &[
    "method",
    "http_method",
    "reqtype",
    "aws.requestParameters.httpMethod",
    // AWS WAF — httpMethod inside httpRequest block
    "aws.httpRequest.httpMethod",
    // AWS S3 Server Access Logs — REST method (DELETE/GET/PUT/POST/…)
    "aws.operation",
    // Cloudflare WAF — HTTP method from the proxied request
    "ClientRequestMethod",
    // Generic HTTP proxy / reverse proxy decoders (underscore variant)
    "request_method",
    // CEF / ArcSight / proxy decoders (camelCase variant)
    "requestMethod",
];

pub(crate) const HTTP_STATUS: &[&str] = &[
    "http_response_code",
    "http_status_code",
    "http_status",
    "response_code",
    "status_code",
    // AWS ALB access log status code
    "aws.elb_status_code",
    // AWS S3 Server Access Logs HTTP status
    "aws.http_status",
    // Cloudflare WAF — HTTP response status code from origin/edge
    "EdgeResponseStatus",
    // GCP: HTTP response status in jsonPayload (Cloud Armor / LB)
    "gcp.jsonPayload.statusCode",
];

pub(crate) const APP_NAME: &[&str] = &[
    "app",
    "application",
    "appName",
    "service",
    "service_name",
    "product_name", // generic product/software name (many vendors)
    "product",      // compact product field
    "product.name", // McAfee / Symantec / FireEye / Kaspersky / RSA decoder field (38 decoders)
    "protocol",     // some decoders re-use protocol as app
    // AWS CloudTrail — which AWS service was called (e.g. "ec2.amazonaws.com")
    "aws.eventSource",
    // AWS CloudTrail — service or principal that invoked the action on behalf of the actor
    "aws.userIdentity.invokedBy",
    // AWS CloudTrail — User-Agent string from the SDK / CLI / console that made the call
    "aws.userAgent",
    // Office365 — workload service that generated the event (Exchange/SharePoint/OneDrive/…)
    "office365.Workload",
    // Office365 — display name of the app (OneDriveSync/OutlookMobile/…)
    "office365.ApplicationDisplayName",
    // Office365 — event source service (SharePoint/Exchange/…)
    "office365.EventSource",
    // Office365 — user-agent of the connecting client
    "office365.UserAgent",
    // AWS ALB — load balancer name
    "aws.elb",
    // AWS WAF — Web ACL ID / name
    "aws.webaclId",
    // Azure — resource/service type
    "azure.resourceType",
    "azure.properties.appDisplayName",
    // Okta — client application / browser
    "okta.target.alternateId",
    "okta.client.userAgent.browser",
    "module", // module name (OpenVPN, Apache modules — 2 decoders)
    // Windows provider / event-log channel names (identify the application)
    "win.system.providerName",
    "win.system.channel",
    // Amazon Security Lake OCSF-native relay — metadata product name
    "metadata.product.name",
    // MongoDB — subsystem/component name that generated the log entry
    "mongodb.component",
    // AWS Security Hub — product that generated the finding (GuardDuty/Inspector/…)
    "aws.finding.ProductName",
    // MS Graph Security — name of the detection engine/product that raised the alert
    "ms-graph.detectionSource",
    // MS Graph Security — Microsoft service that produced the finding
    "ms-graph.serviceSource",
    // MS Graph Security — target resource area (deviceManagement/identityProtection/…)
    "ms-graph.resource",
    // Jenkins CI — component/plugin that generated the event
    "jenkins.component",
    // osquery — query/pack name (identifies the specific scheduled query that triggered)
    "osquery.name",
    "osquery.pack",
];

pub(crate) const FILE_NAME: &[&str] = &[
    "filename",
    "file_id",
    "sysmon.targetfilename",
    "audit.file.name",
    // Office365 SharePoint / OneDrive — original file name before rename/move
    "office365.SourceFileName",
    // Office365 SharePoint — file extension (used when full name not available)
    "office365.SourceFileExtension",
    "TargetPath",
    "TargetFileName", // Check Point / Windows Sysmon (target of file op)
    "SourceFilePath", // Check Point: source file full path
    "ChildPath",      // sysmon process-create: child executable path
    "ParentPath",     // sysmon process-create: parent executable path
    // Windows Defender / Microsoft Security
    "win.eventdata.objectName",
    "defender.path",      // Defender threat path
    "defender.pathfound", // Defender scan hit
    // Antivirus / Cylance / EDR
    "cylance_threats.file_name",
    "cylance_threats.file_path",
    "cylance_events.filepath", // Cylance event filepath
    "infected_file_path",      // generic AV alert field
    "target_file",             // target file in various decoders
    "path",                    // generic path field (syslog, Linux)
    "Path",                    // uppercase variant (CEF / Windows)
    "sysmon.imageLoaded",      // Sysmon event 7: DLL/image being loaded
    "object",                  // Windows audit object path (file/registry)
    "url_filename",            // filename extracted from URL path
    // Sysmon Event 11 — TargetFilename from CreateFile event
    "sysmon.filecreated",
    // Windows Event — file/image name variants from Security and Sysmon events
    "win.eventdata.targetFileName", // capital N — 4663/4656 Object Access
    "win.eventdata.targetFilename", // lowercase n — Sysmon Event 11 via WEF
    "win.eventdata.originalFileName", // original file name before rename
    "win.eventdata.imageLoaded",    // Sysmon Event 7 via WEF (image/DLL path)
    // auditd — directory path component of the file being accessed
    "audit.directory.name",
];

pub(crate) const PROCESS_NAME: &[&str] = &[
    "sysmon.image",
    "sysmon.Image",
    "audit.exe",
    "audit.command",
    // auditd execve arguments — a0 is the executable, a1/a2 are arguments
    "audit.execve.a0",
    "audit.execve.a1",
    "audit.execve.a2",
    "command",
    "program",
    "process",
    // Short command alias used by some decoders
    "cmd",
    "SourceProcessName", // Check Point / Cylance: initiating process
    "ChildProcessName",  // parent-process audit records
    "defender.processname",
    "process.name",       // dot-notation process name (various)
    "sysmon.commandLine", // Sysmon Command Line (full invocation string)
    "sysmon.targetImage", // Sysmon Event 8/10: target process image
    "sysmon.parentImage", // Sysmon parent process image path
    "sysmon.sourceImage", // Sysmon source process (thread injection etc.)
    "win.eventdata.image",
    "win.eventdata.Image",
    "win.eventdata.ProcessName",
    // Windows Event — full command line strings (Process create, PowerShell, etc.)
    "win.eventdata.commandLine",
    "win.eventdata.parentCommandLine",
    // Windows Event — executable image path variants
    "win.eventdata.imagePath",
    "win.eventdata.sourceImage",
    "win.eventdata.parentImage",
    "win.eventdata.targetImage",
    // Program name from structured parameters sub-object
    "parameters.program",
];

pub(crate) const PROCESS_ID: &[&str] = &[
    "sysmon.processId",
    "sysmon.ProcessId",
    "sysmon.processid", // Sysmon lowercase variant (older Wazuh agents)
    "audit.pid",
    "pid",         // generic lowercase PID (netstat, auditd, misc)
    "PID",         // uppercase PID (Check Point, Cylance LEEF)
    "process.pid", // dot-notation PID (docker, nested decoders)
    "win.eventdata.processId",
    "win.eventdata.ProcessId",
    "win.system.execution.processId",
    "sysmon.parentProcessId", // Sysmon parent process PID
    "sqlserver.processid",    // SQL Server audit process id
];

pub(crate) const RULE_NAME: &[&str] = &[
    "rule_name",
    "attack.name",
    "attack",
    "sysmon.signature",
    "sysmon.ruleName", // Sysmon v15+ matching rule name
    "signature",
    "ThreatName",       // Cylance / CrowdStrike threat name
    "AnalyzerRuleName", // Prelude IDMEF analyzer rule name
    // AWS GuardDuty / Inspector / Macie — finding title
    "aws.title",
    // AWS Trusted Advisor — check name (key contains hyphen, resolved via jpath split)
    "aws.check-name",
    // Generic rule/check name from various security product decoders
    "ruleName",
    // Qualys Guard — vulnerability title (for finding events)
    "qualysguard.vulnerability_title",
    // Cylance — threat description used as finding title
    "cylance_threats.description",
    // AWS Security Hub — the CIS/NIST/PCI security control ID that failed
    "aws.finding.Compliance.SecurityControlId",
    // AV / EDR threat / malware names (OCSF malware.name — closest column is rule_name / finding_title)
    "virus",         // ClamAV / generic AV decoder: name of detected virus
    "defender.name", // Windows Defender: threat name (e.g. Trojan:Win32/Emotet)
];

pub(crate) const CATEGORY: &[&str] = &[
    "category",
    "cat",
    "appcat",
    "application_category",
    // PAN-OS / FortiGate
    "subtype",
    "sub_cat",
    "subcat", // no-underscore variant (6 decoders: FortiGate, Arbor)
    // Windows / CEF
    "Category",
    // EDR / AV threat category
    "ThreatCategory",  // Cylance threat category field
    "threat_category", // generic threat category (Trend, Sophos, etc.)
    "log_type",        // log type used as category (some generic syslog decoders)
    // AWS GuardDuty / Macie — finding type (e.g. "UnauthorizedAccess:EC2/TorIPCaller")
    "aws.type",
    // AWS Config — resource type (e.g. "AWS::EC2::SecurityGroup")
    "aws.resourceType",
    // SCA / compliance check type (configuration/policy/audit)
    "sca.type",
    // MariaDB event type (QUERY/CONNECT/DISCONNECT/TABLE/FAILED_CONNECT)
    "mariadb.type",
    // Windows — logon type integer (2=interactive,3=network,10=remoteInteractive,…)
    "win.eventdata.logonType",
    // Office365 — authentication protocol used (FormsCookieAuth/OAuth/…)
    "office365.AuthenticationType",
    // Generic event type field (Suricata, osquery, misc JSON decoders)
    "event.type",
    "event_type",
    // Sub-category / event sub-classification (FortiGate, Cisco, Check Point)
    "subcategory",
    // MS Graph Security — MITRE ATT&CK tactic category of the alert
    "ms-graph.category",
    // MS Graph Security — alert classification (falsePositive/informationalExpectedActivity/…)
    "ms-graph.classification",
    // Docker — entity type being acted upon (container/network/volume/plugin/secret)
    "docker.Type",
    // GCP — resource type of the log source (gce_instance/dns_query/k8s_cluster/…)
    "gcp.resource.type",
    // FortiGate / SonicWall — event sub-type (ike/ssl/user/system/…)
    "log_subtype",
    // Windows Defender — threat category (Trojan/Ransomware/Exploit/…)
    "defender.category",
    // AWS CloudTrail — identity type (IAMUser/AssumedRole/AWSService/IdentityCenterUser/…)
    // OCSF actor.user.type — closest native column is category
    "aws.userIdentity.type",
    // Office365 Exchange — logon type integer (0=Owner/1=Delegate/2=Admin)
    // OCSF logon_type — same concept as win.eventdata.logonType already above
    "office365.InternalLogonType",
    "office365.LogonType",
];

pub(crate) const IFACE_IN: &[&str] = &[
    "srcintf",
    "inbound_interface",
    "interface",
    "packet_incoming_interface",
    "source_zone",
    "srczone",      // zone-based firewall ingress zone
    "in_interface", // generic inbound interface
    "inzone",       // FortiGate ingress zone
    "ifname",
    "if_name", // interface name (pfSense, Linux)
    // AWS VPC Flow — ENI that captured the traffic
    "interfaceId",
    // Zeek/Bro — log path indicates sensor/interface (e.g. "conn", "dns")
    "zeek._path",
    // Router/switch LAN inbound interface (some Cisco/Juniper decoders)
    "lanin",
];

pub(crate) const IFACE_OUT: &[&str] = &[
    "dstintf",
    "outbound_interface",
    "destination_zone",
    "dstzone",       // zone-based firewall egress zone
    "out_interface", // generic outbound interface
    "outzone",       // FortiGate egress zone
    "outintf",       // compact outbound interface name
    "dstinterface",  // FortiGate destination interface
    // Router/switch LAN outbound interface
    "lanout",
];

pub(crate) const SRC_HOSTNAME: &[&str] = &[
    "hostname",
    "srchost",
    "src_host",
    "sourceHostname",
    "source_hostname",
    "dvchost",
    "host",             // generic syslog hostname
    "HostName",         // Prelude / Check Point PascalCase variant
    "AnalyzerHostName", // Prelude IDMEF analyzer host
    "TargetHostName",   // Check Point target device hostname
    "identHostName",    // ident/IDMEF source hostname
    "serial_number",    // Fortinet/SonicWall device serial used as device identifier (7 decoders)
    "win.system.computer",
    "win.eventdata.workstationName",
    "win.eventdata.WorkstationName",
    "srcname",                      // source name / hostname (LEEF, ArcSight)
    "sname",                        // compact source name (some LEEF decoders)
    "caller_computer",              // Windows Security logon: caller computer name
    "machine_name",                 // generic machine name
    "machinename",                  // no-underscore variant
    "sysmon.sourceHostname",        // Sysmon source process host
    "qualysguard.dns_hostname",     // Qualys scan source DNS hostname
    "qualysguard.netbios_hostname", // Qualys scan source NetBIOS hostname
    "firewall_name", // FortiGate/SonicWall/pfSense: device that generated the log (9 decoders)
    // AWS Inspector — hostname of the assessed EC2 instance
    "aws.assetAttributes.hostname",
    // SentinelOne / generic EDR — PascalCase variant (sourceHostname is already above)
    "sourceHostName",
    // Generic system identifier (SonicWall, misc appliance decoders)
    "system_name",
];

pub(crate) const DST_HOSTNAME: &[&str] = &[
    "dsthost",
    "dst_host",
    "destinationHostname",
    "destination_hostname",
    "sysmon.destinationHostname", // Sysmon Event 3: network connection dest host
    "server_name",                // HTTP SNI / TLS server name
    "device_name", // Fortinet / SonicWall / Sophos: name of the destination device (5 decoders)
    // Windows Event — destination hostname for network events (e.g. RDP target)
    "win.eventdata.destination",
    // Office365 — display name of the connecting device (device.name in OCSF)
    "office365.DeviceDisplayName",
    // Threat intelligence — known botnet domain (target/C2 domain)
    "botnedomain",
];

pub(crate) const ACTION: &[&str] = &[
    "action",
    "log_action",
    "Action",            // Check Point / Prelude: PascalCase variant
    "ThreatActionTaken", // Cylance / CrowdStrike EDR response action
    "RegAction",         // registry hive audit action (create/modify/delete)
    "data.action",       // nested data.action from some syslog decoders
    "alert.action",
    "fw_action",
    "act", // CEF
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
    "defender.action", // Windows Defender quarantine / block / allow
    "operation",       // generic operation name (MariaDB, Check Point, OSSIM)
    "rule_action",     // action from the matching rule (Suricata, Snort)
    "utmaction",       // FortiGate UTM action
    // AWS VPC Flow (ACCEPT/REJECT) and WAF (ALLOW/BLOCK) — nested aws.action
    "aws.action",
    // Cloudflare WAF — rule disposition (allow/block/simulate/challenge/unknown)
    "WAFAction",
    // Docker integration — lifecycle event type (create/start/stop/destroy/exec_start/…)
    "docker.Action",
    // Amazon Security Lake OCSF-native relay — activity_name is the human label
    "activity_name",
    // auditd — syscall/event type (open/execve/connect/ptrace/…)
    "audit.type",
    // macOS BSM / open-audit — command class name
    "audit_record.name",
    // GCP Cloud Logging — IAM/API method name (e.g. google.iam.admin.v1.CreateRole)
    "gcp.protoPayload.methodName",
    // GCP Cloud Armor / Firewall rules detail action
    "gcp.jsonPayload.rule_details.action",
    // MariaDB — SQL operation type (INSERT/SELECT/UPDATE/DELETE/CONNECT/…)
    "mariadb.operation",
    // mariadb.action — alternate MariaDB decoder action field name
    "mariadb.action",
    // Jenkins CI — job/build event action (build_started/build_completed/…)
    "jenkins.action",
    // auditd — system call operation name (open/connect/execve/etc.)
    "audit.op",
    // Generic REST API / Azure Monitor operation name
    // OCSF activity_name — describes the operation performed (not an HTTP verb)
    "api.operation",
    "operationName",
];

pub(crate) const STATUS: &[&str] = &[
    "status",
    "result",
    "outcome",
    "reason",      // generic reason/error string (9 decoders: ipsec, vpn, radius)
    "severity",    // vendor severity label used as status text (7 decoders)
    "data.status", // nested data.status from generic decoders
    "cylance_events.eventstatus", // Cylance event status
    "win.eventdata.status",
    "win.eventdata.Status",
    "win.eventdata.failureReason",
    "aws.errorCode",
    // Okta outcome — SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, UNKNOWN
    "okta.outcome.result",
    // Azure AD — "0" = success, non-zero string = error code
    "azure.resultType",
    "azure.resultDescription",
    "audit.res",
    "audit.success",  // auditd success field ("yes"/"no" or "1"/"0")
    "error",          // generic error field (STATUS = error outcome)
    "event.severity", // Prelude/RSA IDMEF analyzer event severity (38 decoders)
    // AWS Trusted Advisor — check status (ERROR / WARN / OK)
    "aws.status",
    // AWS Config — configuration item status (OK / ResourceDiscovered / ResourceDeleted / …)
    "aws.configurationItemStatus",
    // MS Graph Security (Microsoft 365 Defender) — alert lifecycle status
    "ms-graph.status",
    // MS Graph — determination of the alert (malware/phishing/truePositive/falsePositive/…)
    "ms-graph.determination",
    // Docker — container status string (start/stop/kill/die/exec_start/…)
    "docker.status",
    // macOS BSM / open-audit — per-record operation status
    "audit_record.status",
    // GCP — resource/request status from jsonPayload responses
    "gcp.jsonPayload.responseCode",
    // MariaDB — query return code (0 = success, non-zero = error)
    "mariadb.retcode",
    // Qualys Guard — ticket state (Open/Fixed/Re-Opened/Invalid/Ignored)
    "qualysguard.state",
    // Cylance — file quarantine status (Quarantined/Whitelisted/Removed/…)
    "cylance_threats.file_status",
    // Windows Security — hex error/failure codes from logon and access events
    "win.eventdata.errorCode",
    "win.eventdata.failureCode",
    // Windows System log — string severity (Critical/Error/Warning/Information)
    "win.system.severityValue",
    // SCA / CIS compliance check outcome (passed/failed/not applicable)
    "sca.check.result",
    "sca.check.previous_result",
    "cis.result",
    "cis-data.result",
    // OpenSCAP — result per check rule and per scan
    "oscap.check.result",
    "oscap.check.severity",
    "oscap.scan.return_code",
    // VirusTotal integration
    "virustotal.found",
    "virustotal.malicious",
    "virustotal.error",
    // Qualys Guard scan severity level (1–5)
    "qualysguard.severity",
    // DNS RCODE (NOERROR/NXDOMAIN/SERVFAIL/REFUSED/…)
    "rcode",
    // Jenkins CI — job severity / build status
    "jenkins.severity",
    // Sophos XG / UTM firewall status message
    "sophos_fw_status_msg",
    // MongoDB — log severity level (F/E/W/I/D)
    "mongodb.severity",
    // Cisco IOS/ASA — severity number (0=emerg…7=debug) or string label
    "cisco.severity",
    // osquery — status of a monitored column value (added/removed/…)
    "osquery.columns.status",
    // Generic firewall / appliance event status
    "fstatus",
    // Generic resolved flag (DNS, vulnerability, SCA) — "yes"/"no"/"1"/"0"
    "resolved",
    // Generic error_code field (multiple decoders: nginx, haproxy, radius, etc.)
    "error_code",
    // AWS S3 / CloudTrail underscore-variant error code
    "aws.error_code",
    // AWS Security Hub / Config — compliance status of the finding
    "aws.finding.Compliance.Status",
    // AWS Security Hub — record lifecycle state (ACTIVE/ARCHIVED)
    "aws.finding.RecordState",
    // Office365 — result of the operation (Succeeded/Failed/PartiallySucceeded/…)
    "office365.ResultStatus",
];
