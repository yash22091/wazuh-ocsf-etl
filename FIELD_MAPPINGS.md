# Wazuh → OCSF → ClickHouse Field Mapping Reference

> **Purpose**: A complete reference for building Grafana dashboards against the `wazuh_ocsf` database.
> Every typed ClickHouse column is listed with the Wazuh source fields that populate it, grouped by source.
>
> OCSF version: **1.7.0** | All compliance fixes verified March 2026.

---

## Contents

1. [Quick column reference](#1-quick-column-reference)
2. [Detailed column reference by group](#2-detailed-column-reference-by-group)
   - [Time](#21-time)
   - [OCSF event classification](#22-ocsf-event-classification)
   - [Device / agent](#23-device--agent)
   - [Network layer](#24-network-layer)
   - [NAT / translated addresses](#25-nat--translated-addresses)
   - [Identity — actor and target](#26-identity--actor-and-target)
   - [HTTP / web](#27-http--web)
   - [Process and file](#28-process-and-file)
   - [Network context](#29-network-context)
   - [Event context — what happened](#210-event-context--what-happened)
   - [Finding / Wazuh rule](#211-finding--wazuh-rule)
   - [MITRE ATT&CK](#212-mitre-attck)
   - [Vulnerability (class 2002)](#213-vulnerability-class-2002)
   - [Compliance tags](#214-compliance-tags)
   - [Lossless capture columns](#215-lossless-capture-columns)
3. [Per-source mapping tables](#3-per-source-mapping-tables)
   - [Generic Wazuh / syslog](#31-generic-wazuh--syslog)
   - [Windows Event Log](#32-windows-event-log)
   - [AWS CloudTrail](#33-aws-cloudtrail)
   - [AWS VPC Flow Logs](#34-aws-vpc-flow-logs)
   - [AWS GuardDuty / Inspector / Macie](#35-aws-guardduty--inspector--macie)
   - [AWS Security Hub / Config / Trusted Advisor](#36-aws-security-hub--config--trusted-advisor)
   - [Office365 Audit Log](#37-office365-audit-log)
   - [GCP Cloud Logging](#38-gcp-cloud-logging)
   - [Azure AD / Monitor](#39-azure-ad--monitor)
   - [Okta System Log](#310-okta-system-log)
   - [Zeek / Bro network sensor](#311-zeek--bro-network-sensor)
   - [Suricata IDS](#312-suricata-ids)
   - [Wazuh Vulnerability Detector](#313-wazuh-vulnerability-detector)
   - [Wazuh FIM (File Integrity Monitoring)](#314-wazuh-fim-file-integrity-monitoring)
   - [Wazuh SCA (Security Configuration Assessment)](#315-wazuh-sca-security-configuration-assessment)
4. [Extensions column key reference](#4-extensions-column-key-reference)
5. [Sample Grafana SQL queries](#5-sample-grafana-sql-queries)

---

## 1. Quick column reference

All columns that appear in **every** `wazuh_ocsf.ocsf_*` table.  
`LCC` = `LowCardinality(String)`.

| # | ClickHouse column | Type | OCSF 1.7.0 path | Always set? |
|---|---|---|---|---|
| — | **`time`** | `DateTime` | `metadata.processed_time` | ✅ yes |
| — | **`time_dt`** | `String` | `@timestamp` ISO-8601 | ✅ yes |
| — | **`ocsf_version`** | `LCC` | `metadata.version` | ✅ yes |
| — | **`class_uid`** | `UInt32` | `class_uid` | ✅ yes |
| — | **`class_name`** | `LCC` | `class_name` | ✅ yes |
| — | **`category_uid`** | `UInt32` | `category_uid` | ✅ yes |
| — | **`category_name`** | `LCC` | `category_name` | ✅ yes |
| — | **`severity_id`** | `UInt8` | `severity_id` **0–5** | ✅ yes |
| — | **`severity`** | `LCC` | `severity` label | ✅ yes |
| — | **`activity_id`** | `UInt8` | `activity_id` | ✅ yes |
| — | **`activity_name`** | `LCC` | `activity_name` | ✅ yes |
| — | **`type_uid`** | `UInt32` | `type_uid` = class×100+activity | ✅ yes |
| — | **`status_id`** | `UInt8` | `status_id` | ✅ yes |
| — | **`confidence_id`** | `UInt8` | `confidence_id` | ✅ yes |
| — | **`status`** | `LCC` | `status` free-text | when present |
| — | **`action`** | `LCC` | `activity.action` free-text | when present |
| 1 | **`src_ip`** | `String` | `src_endpoint.ip` | when present |
| 2 | **`dst_ip`** | `String` | `dst_endpoint.ip` | when present |
| 3 | **`src_port`** | `UInt16` | `src_endpoint.port` | when present |
| 4 | **`dst_port`** | `UInt16` | `dst_endpoint.port` | when present |
| 5 | **`nat_src_ip`** | `String` | `src_endpoint.intermediate_ips[0]` | when present |
| 6 | **`nat_dst_ip`** | `String` | `dst_endpoint.intermediate_ips[0]` | when present |
| 7 | **`nat_src_port`** | `UInt16` | `src_endpoint.intermediate_port` | when present |
| 8 | **`nat_dst_port`** | `UInt16` | `dst_endpoint.intermediate_port` | when present |
| 9 | **`network_protocol`** | `LCC` | `connection_info.protocol_name` | when present |
| 10 | **`bytes_in`** | `UInt64` | `traffic.bytes_in` | when present |
| 11 | **`bytes_out`** | `UInt64` | `traffic.bytes_out` | when present |
| 12 | **`actor_user`** | `String` | `actor.user.name` | when present |
| 13 | **`target_user`** | `String` | `dst_endpoint.user.name` | when present |
| 14 | **`domain`** | `LCC` | `actor.user.domain` / `cloud.account_uid` | when present |
| 15 | **`url`** | `String` | `http_request.url.text` | when present |
| 16 | **`http_method`** | `LCC` | `http_request.http_method` | when present |
| 17 | **`http_status`** | `UInt16` | `http_response.code` | when present |
| 18 | **`app_name`** | `LCC` | `app.name` / `product.name` | when present |
| 19 | **`src_hostname`** | `LCC` | `src_endpoint.hostname` | when present |
| 20 | **`dst_hostname`** | `LCC` | `dst_endpoint.hostname` | when present |
| 21 | **`file_name`** | `String` | `file.name` / `file.path` | when present |
| 22 | **`process_name`** | `String` | `process.name` / `process.cmd_line` | when present |
| 23 | **`process_id`** | `UInt32` | `process.pid` | when present |
| 24 | **`interface_in`** | `LCC` | `src_endpoint.interface_name` | when present |
| 25 | **`interface_out`** | `LCC` | `dst_endpoint.interface_name` | when present |
| 26 | **`rule_name`** | `String` | `finding.title` (threat/rule name) | when present |
| 27 | **`app_category`** | `LCC` | `category` (event sub-classification) | when present |
| 28 | **`finding_uid`** | `LCC` | `finding.uid` = Wazuh rule ID | ✅ yes |
| 29 | **`finding_title`** | `String` | `finding.title` = rule description | ✅ yes |
| — | **`finding_types`** | `String` (JSON) | `finding.types[]` = rule groups | ✅ yes |
| — | **`wazuh_rule_level`** | `UInt8` | *(Wazuh native)* severity 1–15 | ✅ yes |
| — | **`wazuh_fired_times`** | `UInt32` | *(Wazuh native)* | ✅ yes |
| — | **`attack_technique`** | `String` | `attacks[0].technique.name` | when present |
| — | **`attack_id`** | `String` | `attacks[0].technique.uid` | when present |
| — | **`attack_tactic`** | `String` | `attacks[0].tactic.name` | when present |
| — | **`cve_id`** | `LCC` | `finding.vulnerabilities[0].cve.uid` | vuln class |
| — | **`cvss_score`** | `Float32` | `finding.vulnerabilities[0].cvss[0].base_score` | vuln class |
| — | **`pci_dss`** | `String` | *(Wazuh compliance tag)* | when present |
| — | **`gdpr`** | `String` | *(Wazuh compliance tag)* | when present |
| — | **`hipaa`** | `String` | *(Wazuh compliance tag)* | when present |
| — | **`nist_800_53`** | `String` | *(Wazuh compliance tag)* | when present |
| — | **`device_uid`** | `String` | `device.uid` = agent ID | ✅ yes |
| — | **`device_name`** | `LCC` | `device.name` = agent name | ✅ yes |
| — | **`device_ip`** | `String` | `device.ip` = agent IP | ✅ yes |
| — | **`decoder_name`** | `LCC` | *(Wazuh native)* | ✅ yes |
| — | **`manager_name`** | `LCC` | *(Wazuh native)* | ✅ yes |
| — | **`src_location`** | `String` | `metadata.log_provider` | ✅ yes |
| — | **`event_data`** | `String` (JSON) | Full `data.*` subtree | ✅ yes |
| — | **`extensions`** | `String` (JSON) | Custom + overflow fields | ✅ yes |
| — | **`unmapped`** | `String` (JSON) | Unknown top-level keys | ✅ yes |
| — | **`raw_data`** | `String` (JSON) | Full raw Wazuh alert (disable via `STORE_RAW_DATA=false`) | ✅ yes |

---

## 2. Detailed column reference by group

### 2.1 Time

| Column | Type | Notes |
|---|---|---|
| `time` | `DateTime` | Primary ORDER BY key. Use in WHERE: `time >= now() - INTERVAL 1 HOUR` |
| `time_dt` | `String` | ISO-8601 copy for display; less efficient to filter — prefer `time` |

**Source:** `@timestamp` or `timestamp` field in the Wazuh alert JSON. Falls back to `now()` if unparseable.

---

### 2.2 OCSF event classification

Automatically derived — no config required.

| Column | Values | Description |
|---|---|---|
| `class_uid` | 1001, 1006, 2002, 2003, 2004, 3001, 3002, 4001, 4002, 4003, 4004 | OCSF class integer |
| `class_name` | `File System Activity`, `Process Activity`, `Vulnerability Finding`, `Compliance Finding`, `Detection Finding`, `Account Change`, `Authentication`, `Network Activity`, `HTTP Activity`, `DNS Activity`, `DHCP Activity` | Human-readable class |
| `category_uid` | 1–4 | 1=System, 2=Findings, 3=Identity, 4=Network |
| `category_name` | `System Activity`, `Findings`, `Identity & Access Management`, `Network Activity` | |
| `severity_id` | 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical | Mapped from `wazuh_rule_level` (see table below) |
| `severity` | Unknown / Informational / Low / Medium / High / Critical | String label |
| `status_id` | 0=Unknown, 1=New (findings) or Success (ops), 2=InProgress/Failure, 3=Suppressed, 4=Resolved, 99=Other | Context-dependent — see README 15 |
| `activity_id` | Class-dependent | See README 15 for per-class values |
| `type_uid` | = `class_uid * 100 + activity_id` | OCSF required derived field |

**Severity mapping from Wazuh rule level:**

| `wazuh_rule_level` | `severity_id` | `severity` |
|---|---|---|
| 0 | 0 | Unknown |
| 1 – 3 | 1 | Informational |
| 4 – 6 | 2 | Low |
| 7 – 9 | 3 | Medium |
| 10 – 12 | 4 | High |
| 13 – 15 | 5 | Critical |

> **Override sources:** Wazuh Vulnerability Detector (Low/Medium/High/Critical), AWS GuardDuty (0.0–9.9 float), GCP (EMERGENCY/ALERT/CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG), Docker (`error`/`warning`/`info`), MS Graph (`informational`/`low`/`medium`/`high`) all override the default rule-level mapping when present.

---

### 2.3 Device / agent

| Column | Wazuh source field | Notes |
|---|---|---|
| `device_uid` | `agent.id` | Wazuh agent UUID |
| `device_name` | `agent.name` | Hostname as registered in Wazuh — use this for Grafana variable `$agent` |
| `device_ip` | `agent.ip` | Management IP of the agent |
| `manager_name` | `manager.name` | Wazuh manager/node hostname (important for cluster deployments) |
| `decoder_name` | `decoder.name` | Wazuh decoder that parsed the raw log line |
| `src_location` | `location` | Log file path or integration name (e.g. `/var/log/syslog`, `aws-cloudtrail`) |

---

### 2.4 Network layer

| Column | Type | Key source fields (by vendor) |
|---|---|---|
| `src_ip` | `String` | **Generic:** `srcip`, `src_ip`, `IP`, `client`, `xff_address` · **Windows:** `win.eventdata.ipAddress`, `win.eventdata.sourceAddress` · **AWS:** `aws.sourceIPAddress`, `aws.source_ip_address`, `aws.httpRequest.clientIp`, `aws.remote_ip`, `aws.summary.IP` · **GCP:** `gcp.protoPayload.requestMetadata.callerIp` · **Azure:** `azure.callerIpAddress`, `azure.properties.ipAddress`, `azure.properties.clientIP` · **Okta:** `okta.client.ipAddress` · **Office365:** `office365.ClientIP`, `office365.ClientIPAddress`, `office365.ActorIpAddress` · **Zeek:** `zeek.id.orig_h` · **Suricata:** `alert.src_ip` · **MariaDB:** `mariadb.ip` · **GuardDuty:** `aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4` · **VPC Flow:** `srcAddr`, `aws.srcaddr` · **GitHub:** `github.actor_ip` |
| `dst_ip` | `String` | **Generic:** `dstip`, `dst_ip`, `destination_ip` · **Windows:** `win.eventdata.destinationIp` · **Zeek:** `zeek.id.resp_h` · **VPC Flow:** `dstAddr`, `aws.dstaddr` · **GuardDuty:** `aws.service.action.networkConnectionAction.localIpDetails.ipAddressV4` · **Qualys:** `qualysguard.ip` |
| `src_port` | `UInt16` | **Generic:** `srcport`, `src_port`, `sport` · **Windows:** `win.eventdata.ipPort` · **VPC Flow:** `srcPort`, `aws.srcport` · **Zeek:** `zeek.id.orig_p` · **GuardDuty:** `aws.service.action.networkConnectionAction.remotePortDetails.port` |
| `dst_port` | `UInt16` | **Generic:** `dstport`, `dst_port`, `dport` · **Windows:** `win.eventdata.destinationPort` · **VPC Flow:** `dstPort`, `aws.dstport` · **Zeek:** `zeek.id.resp_p` · **GuardDuty:** `aws.service.action.networkConnectionAction.localPortDetails.port` |
| `network_protocol` | `String` | **Generic:** `protocol`, `proto` · **Windows:** `win.eventdata.protocol` · **AWS:** `aws.protocol` |
| `bytes_in` | `UInt64` | **FortiGate:** `rcvdbyte` · **Generic:** `bytes_recv`, `bytes_in`, `BytesReceived` · **AWS S3/CloudTrail:** `aws.additionalEventData.bytesTransferredIn` · **VPC Flow:** `aws.bytes` |
| `bytes_out` | `UInt64` | **FortiGate:** `sentbyte` · **Generic:** `bytes_sent`, `bytes_out`, `BytesSent` · **AWS:** `aws.additionalEventData.bytesTransferredOut` |

---

### 2.5 NAT / translated addresses

| Column | Key source fields |
|---|---|
| `nat_src_ip` | `nat_srcip`, `transip` (FortiGate), `mapped_src_ip`, `xlatesrc` (Check Point) |
| `nat_dst_ip` | `nat_dstip`, `mapped_dst_ip`, `xlatedst` (Check Point) |
| `nat_src_port` | `nat_srcport`, `transport` (FortiGate), `xlatesport` (Check Point) |
| `nat_dst_port` | `nat_dstport`, `mapped_dst_port`, `xlatedport` (Check Point) |

---

### 2.6 Identity — actor and target

| Column | Type | Key source fields (by vendor) |
|---|---|---|
| `actor_user` | `String` | **Generic:** `user`, `username`, `srcuser`, `login`, `account_name` · **audit:** `audit.acct`, `audit.auid` · **Windows:** `win.eventdata.subjectUserName`, `win.eventdata.SubjectUserName`, `win.eventdata.subjectAccountName` · **AWS:** `aws.userIdentity.userName`, `aws.userIdentity.arn`, `aws.requester` · **GCP:** `gcp.protoPayload.authenticationInfo.principalEmail` · **Azure:** `azure.properties.userPrincipalName` · **Okta:** `okta.actor.alternateId`, `okta.actor.displayName` · **Office365:** `office365.UserId`, `office365.UserKey`, `office365.actor` · **GitHub:** `github.actor` · **MariaDB:** `mariadb.username` · **LDAP:** `ldap_data.Username` · **Amazon Security Lake:** `identity.user.name` |
| `target_user` | `String` | **Generic:** `dstuser`, `new_user`, `removed_user` · **Windows:** `win.eventdata.targetUserName`, `win.eventdata.TargetUserName`, `win.eventdata.targetUserSid` |
| `domain` | `String` | **Generic:** `domain`, `account_domain` · **Windows:** `win.eventdata.subjectDomainName`, `win.eventdata.targetDomainName` · **AWS:** `aws.userIdentity.accountId`, `aws.recipientAccountId`, `aws.awsRegion` · **Azure:** `azure.tenantId` · **GCP:** `gcp.resource.labels.project_id` · **Office365:** `office365.OrganizationId` · **GitHub:** `github.org` · **MariaDB:** `mariadb.database` · **GitLab:** `project_path` |

---

### 2.7 HTTP / web

| Column | Type | Key source fields (by vendor) |
|---|---|---|
| `url` | `String` | **Generic:** `url`, `uri`, `request_uri`, `request` · **Windows:** `win.eventdata.objectName`, `win.eventdata.shareName` · **AWS:** `aws.requestParameters.url`, `aws.requestParameters.bucketName`, `aws.request_uri`, `aws.httpRequest.uri`, `aws.additionalEventData.LoginTo` · **GCP:** `gcp.protoPayload.resourceName` · **Office365:** `office365.ObjectId`, `office365.SiteUrl`, `office365.SourceRelativeUrl` · **Okta:** `okta.target.displayName` · **Azure:** `azure.properties.resourceUri` · **GitHub:** `github.repo` · **Cloudflare:** `ClientRequestURI` |
| `http_method` | `String` | **Generic:** `method`, `http_method`, `reqtype`, `request_method`, `requestMethod` · **AWS:** `aws.requestParameters.httpMethod`, `aws.httpRequest.httpMethod`, `aws.operation` · **Cloudflare:** `ClientRequestMethod` |
| `http_status` | `UInt16` | **Generic:** `http_response_code`, `http_status`, `status_code` · **AWS ALB:** `aws.elb_status_code` · **AWS S3:** `aws.http_status` · **Cloudflare:** `EdgeResponseStatus` · **GCP:** `gcp.jsonPayload.statusCode` |

---

### 2.8 Process and file

| Column | Type | Key source fields (by vendor) |
|---|---|---|
| `process_name` | `String` | **Generic:** `command`, `program`, `process`, `cmd` · **audit:** `audit.exe`, `audit.command`, `audit.execve.a0` · **Sysmon:** `sysmon.image`, `sysmon.commandLine`, `sysmon.parentImage`, `sysmon.targetImage` · **Windows:** `win.eventdata.image`, `win.eventdata.ProcessName`, `win.eventdata.commandLine`, `win.eventdata.parentCommandLine`, `win.eventdata.imagePath`, `win.eventdata.sourceImage` · **Defender:** `defender.processname` |
| `process_id` | `UInt32` | **Generic:** `pid`, `PID`, `process.pid` · **audit:** `audit.pid` · **Sysmon:** `sysmon.processId` · **Windows:** `win.eventdata.processId`, `win.system.execution.processId` · **SQL Server:** `sqlserver.processid` |
| `file_name` | `String` | **Generic:** `filename`, `path`, `Path`, `object`, `target_file` · **Syscheck:** `syscheck.path` (FIM) · **audit:** `audit.file.name`, `audit.directory.name` · **Sysmon:** `sysmon.targetfilename`, `sysmon.imageLoaded`, `sysmon.filecreated` · **Windows:** `win.eventdata.targetFileName`, `win.eventdata.originalFileName`, `win.eventdata.imageLoaded` · **Office365 SP:** `office365.SourceFileName` · **Cylance:** `cylance_threats.file_name`, `cylance_threats.file_path` · **AV:** `infected_file_path` |

---

### 2.9 Network context

| Column | Type | Key source fields (by vendor) |
|---|---|---|
| `src_hostname` | `String` | **Generic:** `hostname`, `srchost`, `host` · **Windows:** `win.system.computer`, `win.eventdata.workstationName` · **Sysmon:** `sysmon.sourceHostname` · **Predecoder:** `predecoder.hostname` · **Qualys:** `qualysguard.dns_hostname`, `qualysguard.netbios_hostname` · **AWS Inspector:** `aws.assetAttributes.hostname` |
| `dst_hostname` | `String` | **Generic:** `dsthost`, `server_name`, `device_name` · **Sysmon:** `sysmon.destinationHostname` · **Windows:** `win.eventdata.destination` · **Office365:** `office365.DeviceDisplayName` · **Threat intel:** `botnedomain` |
| `interface_in` | `String` | **Generic:** `srcintf`, `inbound_interface`, `interface`, `source_zone` · **FortiGate:** `inzone` · **VPC Flow:** `interfaceId` · **pfSense:** `ifname` · **Zeek:** `zeek._path` |
| `interface_out` | `String` | **Generic:** `dstintf`, `outbound_interface`, `destination_zone` · **FortiGate:** `outzone`, `dstinterface` |

---

### 2.10 Event context — what happened

| Column | Type | Key source fields (by vendor) |
|---|---|---|
| `action` | `String` | **Generic:** `action`, `act` (CEF), `operation`, `rule_action` · **Windows / Defender:** `defender.action` · **AWS:** `aws.eventName`, `aws.action` (VPC Flow/WAF) · **GCP:** `gcp.protoPayload.methodName`, `gcp.jsonPayload.rule_details.action` · **Azure:** `azure.operationName`, `azure.properties.operationType` · **Okta:** `okta.displayMessage`, `okta.eventType` · **Office365:** `office365.Operation` · **GitHub:** `github.action` · **Docker:** `docker.Action` · **MariaDB:** `mariadb.operation`, `mariadb.action` · **audit:** `audit.type`, `audit.op` · **API / REST:** `api.operation`, `operationName` · **Cloudflare WAF:** `WAFAction` |
| `status` | `String` | **Generic:** `status`, `result`, `outcome`, `error`, `reason` · **audit:** `audit.res`, `audit.success` · **Windows:** `win.eventdata.status`, `win.eventdata.failureReason`, `win.eventdata.errorCode`, `win.system.severityValue` · **AWS:** `aws.errorCode`, `aws.status`, `aws.configurationItemStatus`, `aws.finding.Compliance.Status`, `aws.finding.RecordState` · **Okta:** `okta.outcome.result` (SUCCESS / FAILURE / ALLOW / DENY) · **Azure:** `azure.resultType`, `azure.resultDescription` · **MS Graph:** `ms-graph.status`, `ms-graph.determination` · **Docker:** `docker.status` · **SCA:** `sca.check.result` · **VirusTotal:** `virustotal.found`, `virustotal.malicious` · **Office365:** `office365.ResultStatus` · **DNS:** `rcode` · **MariaDB:** `mariadb.retcode` |
| `app_name` | `String` | **Generic:** `app`, `application`, `service`, `product.name`, `module` · **Windows:** `win.system.providerName`, `win.system.channel` · **Predecoder:** `predecoder.program_name` · **AWS:** `aws.eventSource`, `aws.userIdentity.invokedBy`, `aws.userAgent`, `aws.finding.ProductName`, `aws.elb`, `aws.webaclId` · **GCP:** `gcp.resource.type` · **Azure:** `azure.resourceType`, `azure.properties.appDisplayName` · **Okta:** `okta.client.userAgent.browser` · **Office365:** `office365.Workload`, `office365.ApplicationDisplayName`, `office365.EventSource` · **MS Graph:** `ms-graph.detectionSource`, `ms-graph.serviceSource` · **MongoDB:** `mongodb.component` · **osquery:** `osquery.name`, `osquery.pack` · **Jenkins:** `jenkins.component` |
| `app_category` | `String` | **Generic:** `category`, `subtype`, `log_type`, `event.type`, `event_type`, `subcategory` · **Windows:** `win.eventdata.logonType` · **AWS:** `aws.type` (GuardDuty finding type), `aws.resourceType`, `aws.userIdentity.type` ⚠️ (IAMUser/AssumedRole/AWSService) · **GCP:** `gcp.resource.type` · **Office365:** `office365.AuthenticationType`, `office365.InternalLogonType` ⚠️, `office365.LogonType` ⚠️ · **MS Graph:** `ms-graph.category`, `ms-graph.classification` · **Docker:** `docker.Type` · **Defender:** `defender.category` · **SCA:** `sca.type` · **MariaDB:** `mariadb.type` |
| `rule_name` | `String` | **Generic:** `rule_name`, `signature`, `ThreatName` · **Sysmon:** `sysmon.signature`, `sysmon.ruleName` · **AWS:** `aws.title` (GuardDuty/Inspector finding), `aws.check-name`, `aws.finding.Compliance.SecurityControlId` · **MS Graph:** `ms-graph.title` · **Qualys:** `qualysguard.vulnerability_title` · **Cylance:** `cylance_threats.description` · **AV/EDR:** `virus` (ClamAV), `defender.name` (Windows Defender threat) |

> ⚠️ `aws.userIdentity.type`, `office365.InternalLogonType`, `office365.LogonType` — these are **classification integers / type codes**, not status outcomes. They are correctly mapped to `app_category` (OCSF `category` field), not `status`. OCSF 1.7.0 compliance-verified March 2026.

---

### 2.11 Finding / Wazuh rule

These columns are populated from every Wazuh alert's `rule.*` section. Always present.

| Column | Source field | Type | Example value |
|---|---|---|---|
| `finding_uid` | `rule.id` | `LowCardinality(String)` | `"5763"` |
| `finding_title` | `rule.description` | `String` | `"SSH brute force attack"` |
| `finding_types` | `rule.groups` | `String` (JSON array) | `["sshd","authentication_failed","brute_force"]` |
| `wazuh_rule_level` | `rule.level` | `UInt8` | `12` |
| `wazuh_fired_times` | `rule.firedtimes` | `UInt32` | `7` |

> `finding_title` may be overridden by source-specific extraction:
> - SCA: `sca.check.title` (more specific than generic rule description)
> - Vulnerability Detector: the CVE / package info takes priority

---

### 2.12 MITRE ATT&CK

Only populated when Wazuh rule has MITRE mappings.

| Column | Source field | Example |
|---|---|---|
| `attack_technique` | `rule.mitre.technique[]` | `"Brute Force"` |
| `attack_id` | `rule.mitre.id[]` | `"T1110"` |
| `attack_tactic` | `rule.mitre.tactic[]` | `"Credential Access"` |

Query pattern: `WHERE attack_tactic LIKE '%Credential Access%'` or `WHERE attack_id = 'T1110'`

---

### 2.13 Vulnerability (class 2002)

Only populated when `class_uid = 2002`.

| Column | Source field | Type | Notes |
|---|---|---|---|
| `cve_id` | `vulnerability.cve` | `LowCardinality(String)` | e.g. `"CVE-2025-61984"` |
| `cvss_score` | `vulnerability.cvss.cvss3.base_score` | `Float32` | 0.0 – 10.0 |
| `severity` / `severity_id` | `vulnerability.severity` label | Scanner label overrides rule level | Low→2, Medium→3, High→4, Critical→5 |
| `url` | `vulnerability.reference` | `String` | Advisory URL |
| `app_name` | `vulnerability.package.name` | `String` | Affected package |
| `status` | `vulnerability.status` | `String` | `"Active"`, `"Obsolete"` |

---

### 2.14 Compliance tags

Comma-separated lists; use `LIKE` to filter.

| Column | Source field | Example value |
|---|---|---|
| `pci_dss` | `rule.pci_dss` | `"10.2.4,10.2.5"` |
| `gdpr` | `rule.gdpr` | `"IV_35.7.d"` |
| `hipaa` | `rule.hipaa` | `"164.312.b"` |
| `nist_800_53` | `rule.nist_800_53` | `"AU-14,AC-7"` |

---

### 2.15 Lossless capture columns

No data is ever dropped. Four additional columns capture everything not in a typed column:

| Column | Contents |
|---|---|
| `event_data` | Full `data.*` subtree from the Wazuh alert (raw vendor fields, JSON string) |
| `extensions` | Custom-mapped extras + predefined sub-fields (see 4) |
| `unmapped` | Unknown top-level JSON keys from the Wazuh alert (rarely populated) |
| `raw_data` | The complete original Wazuh JSON alert line. Disabled (empty string) when `STORE_RAW_DATA=false` — all other columns are unaffected |

---

## 3. Per-source mapping tables

### 3.1 Generic Wazuh / syslog

For events decoded by standard Linux/UNIX decoders (sshd, sudo, auditd, cron, kernel, etc.).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `rule.id` | `finding_uid` | Always |
| `rule.description` | `finding_title` | Always |
| `rule.level` | `wazuh_rule_level` → `severity_id` | Always |
| `srcip` / `src_ip` / `IP` | `src_ip` | Syslog source |
| `dstip` / `dst_ip` | `dst_ip` | Syslog destination |
| `srcport` / `src_port` | `src_port` | |
| `dstport` / `dst_port` | `dst_port` | |
| `user` / `srcuser` / `username` | `actor_user` | SSH/sudo/PAM |
| `hostname` / `host` / `srchost` | `src_hostname` | |
| `dsthost` / `server_name` | `dst_hostname` | |
| `url` / `uri` / `request` | `url` | Web proxy / HTTP |
| `method` / `http_method` | `http_method` | |
| `http_response_code` / `http_status` | `http_status` | |
| `app` / `service` / `program` | `app_name` | |
| `command` / `process` / `cmd` | `process_name` | |
| `pid` / `PID` | `process_id` | |
| `filename` / `path` | `file_name` | |
| `status` / `result` / `outcome` | `status` | |
| `action` / `act` | `action` | |
| `protocol` / `proto` | `network_protocol` | |
| `bytes_in` / `rcvdbyte` | `bytes_in` | |
| `bytes_out` / `sentbyte` | `bytes_out` | |
| `domain` | `domain` | |
| `category` / `subtype` | `app_category` | |
| `predecoder.hostname` | `src_hostname` | Fallback |
| `predecoder.program_name` | `app_name` | Fallback |

---

### 3.2 Windows Event Log

Events decoded by `windows_eventchannel` / `windows-eventchannel` decoder.

| Wazuh field | ClickHouse column | Example / Notes |
|---|---|---|
| `win.system.providerName` | `app_name` | `"Microsoft-Windows-Security-Auditing"` |
| `win.system.processID` | `process_id` | PID of the event-generating process |
| `win.eventdata.processName` | `process_name` | Full path or process name |
| `win.eventdata.commandLine` | `process_name` | Full command line (Event ID 4688) |
| `win.eventdata.subjectUserName` | `actor_user` | Initiating user (falls back to SID) |
| `win.eventdata.targetUserName` | `target_user` | Target account (falls back to SID) |
| `win.eventdata.subjectDomainName` | `domain` | NTLM/Kerberos domain |
| `win.eventdata.targetDomainName` | `domain` | Target domain |
| `win.eventdata.workstationName` | `src_hostname` | Workstation name |
| `win.eventdata.ipAddress` | `src_ip` | Remote IP for logon events |
| `win.eventdata.destinationIp` | `dst_ip` | Sysmon Event 3 |
| `win.eventdata.destinationPort` | `dst_port` | Sysmon Event 3 |
| `win.eventdata.ipPort` | `src_port` | Remote port for logon events |
| `win.eventdata.objectName` | `file_name` / `url` | File path or share name |
| `win.eventdata.targetFileName` | `file_name` | Object Access events |
| `win.eventdata.imageLoaded` | `file_name` | Sysmon Event 7 (DLL load) |
| `win.eventdata.logonType` | `app_category` | Integer (2=interactive, 3=network, 10=remote) |
| `win.eventdata.status` / `failureReason` | `status` | Logon failure codes |
| `win.eventdata.errorCode` / `failureCode` | `status` | Additional failure info |
| `win.system.channel` | `app_name` | e.g. `"Security"`, `"Application"` |
| `win.system.computer` | `src_hostname` | Computer name |
| **Extensions sub-fields** | | |
| `win.system.eventID` | `extensions.win_event_id` | e.g. `"4624"`, `"4625"` |
| `win.system.channel` | `extensions.win_channel` | `"Security"`, `"System"` |
| `win.eventdata.logonType` | `extensions.win_logon_type` | Integer string |
| `win.eventdata.param1`–`param7` | `extensions.win_param1`–`win_param7` | SCM/service event context |
| `win.eventdata.binary` | `extensions.win_event_binary` | Hex-encoded raw event data |

> **Important for dashboards:** Filter on `extensions.win_event_id` to find specific Windows event types. Use `JSONExtractString(extensions, 'win_event_id')` in ClickHouse.

---

### 3.3 AWS CloudTrail

Events decoded by `aws-cloudtrail` / `cloudtrail` decoder.

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `aws.sourceIPAddress` / `aws.source_ip_address` | `src_ip` | API caller IP |
| `aws.additionalEventData.UserName` | `actor_user` | Human email (IAM Identity Center) |
| `aws.userIdentity.userName` | `actor_user` | IAM username |
| `aws.userIdentity.arn` | `actor_user` | Fallback ARN (AssumedRole, service) |
| `aws.requester` | `actor_user` | S3 Server Access IAM requester |
| `aws.userIdentity.accountId` | `domain` | AWS account ID |
| `aws.awsRegion` | `domain` | AWS region |
| `aws.eventName` | `action` | API operation (e.g. `"CreateUser"`) |
| `aws.eventType` | `action` | CloudTrail event type (AwsApiCall/AwsConsoleAction/…) |
| `aws.eventCategory` | `app_category` | Management / Data |
| `aws.eventSource` | `app_name` | Service endpoint (e.g. `"ec2.amazonaws.com"`) |
| `aws.userAgent` | `app_name` | SDK/CLI/Console label |
| `aws.tlsDetails.clientProvidedHostHeader` | `dst_hostname` | AWS service endpoint |
| `aws.additionalEventData.LoginTo` | `url` | Console SSO redirect URL |
| `aws.responseElements.ConsoleLogin` | `status` | Login result |
| `aws.errorCode` | `status` | Error code → status=Failure |
| `aws.userIdentity.type` | `app_category` | IAMUser / AssumedRole / AWSService |
| `aws.userIdentity.sessionContext.sessionIssuer.arn` | `actor_user` | Role ARN (fallback when no userName) |
| **Extensions sub-fields** | | |
| `aws.eventID` | `extensions.aws_event_id` | UUID |
| `aws.awsRegion` | `extensions.aws_region` | e.g. `"us-east-1"` |
| `aws.userAgent` | `extensions.aws_user_agent` | SDK/CLI/browser |
| `aws.userIdentity.type` | `extensions.aws_identity_type` | IAMUser/AssumedRole/… |
| `aws.additionalEventData.MFAUsed` | `extensions.aws_mfa_used` | `"Yes"` / `"No"` |
| `aws.additionalEventData.MFAIdentifier` | `extensions.aws_mfa_identifier` | MFA device ARN |
| `aws.eventTime` | `extensions.aws_event_time` | ISO 8601 event timestamp |
| `aws.userIdentity.sessionContext.sessionIssuer.type` | `extensions.aws_session_issuer_type` | Role / User |
| `aws.userIdentity.sessionContext.sessionIssuer.principalId` | `extensions.aws_session_principal_id` | Principal UUID |
| `aws.userIdentity.sessionContext.sessionIssuer.accountId` | `extensions.aws_session_issuer_account` | Owning account |
| `aws.userIdentity.sessionContext.attributes.mfaAuthenticated` | `extensions.aws_session_mfa_auth` | true / false |
| `aws.userIdentity.sessionContext.attributes.creationDate` | `extensions.aws_session_created_at` | Session creation time |
| `aws.userIdentity.sessionContext.webIdFederationData.federatedProvider` | `extensions.aws_federated_provider` | OIDC/SAML provider |
| `aws.requestParameters.networkInterfaceId` | `extensions.aws_req_network_interface_id` | ENI ID |
| `aws.requestParameters.groupId` | `extensions.aws_req_security_group_id` | Security group ID |
| `aws.requestParameters.subnetId` | `extensions.aws_req_subnet_id` | Subnet ID |
| `aws.requestParameters.snapshotId` | `extensions.aws_req_snapshot_id` | EBS snapshot ID |
| `aws.requestParameters.volumeId` | `extensions.aws_req_volume_id` | EBS volume ID |
| `aws.requestParameters.allocationId` | `extensions.aws_req_allocation_id` | EIP allocation ID |
| `aws.responseElements.publicIp` | `extensions.aws_res_public_ip` | Allocated public IP |
| `aws.responseElements.networkInterfaceId` | `extensions.aws_res_network_interface_id` | Returned ENI ID |
| `aws.responseElements.allocationId` | `extensions.aws_res_allocation_id` | Returned EIP allocation ID |
| `aws.responseElements.snapshotId` | `extensions.aws_res_snapshot_id` | Created snapshot ID |
| `aws.responseElements.volumeId` | `extensions.aws_res_volume_id` | Created volume ID |
| `aws.tlsDetails.tlsVersion` | `extensions.tls_version` | e.g. `"TLSv1.2"` |
| `aws.resources.ARN` | `extensions.aws_resource_arn` | |
| `aws.errorMessage` | `extensions.aws_error_message` | API error detail |
| `aws.requestID` | `extensions.aws_request_id` | |
| `aws.recipientAccountId` | `extensions.aws_recipient_account_id` | Cross-account |

---

### 3.4 AWS VPC Flow Logs

Events decoded by `aws-vpcflow` decoder. Class 4001 (Network Activity).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `srcAddr` / `aws.srcaddr` | `src_ip` | Source IP |
| `dstAddr` / `aws.dstaddr` | `dst_ip` | Destination IP |
| `srcPort` / `aws.srcport` | `src_port` | Source port (numeric) |
| `dstPort` / `aws.dstport` | `dst_port` | Destination port (numeric) |
| `aws.protocol` | `network_protocol` | Protocol number/name |
| `aws.bytes` | `bytes_in` | Flow byte count |
| `aws.action` | `action` | ACCEPT / REJECT |
| `interfaceId` | `interface_in` | ENI that captured the flow |

---

### 3.5 AWS GuardDuty / Inspector / Macie

Events decoded by `aws-guardduty` decoder. Class 2002 (Vulnerability Finding).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4` | `src_ip` | Attacker IP |
| `aws.service.action.networkConnectionAction.localIpDetails.ipAddressV4` | `dst_ip` | Target (victim) IP |
| `aws.service.action.networkConnectionAction.remotePortDetails.port` | `src_port` | Attacker port |
| `aws.service.action.networkConnectionAction.localPortDetails.port` | `dst_port` | Victim port |
| `aws.title` | `rule_name` | Finding title |
| `aws.type` | `app_category` | Finding type (e.g. `"UnauthorizedAccess:EC2/TorIPCaller"`) |
| `aws.accountId` | `domain` | Target AWS account |
| `aws.severity` (0.0–9.9 float) | `severity` / `severity_id` | GuardDuty numeric severity override |
| Inspector / Macie severity label | `severity` / `severity_id` | Low/Medium/High/Critical → 2/3/4/5 |
| `aws.service.action.actionType` | `action` | NETWORK_CONNECTION / PORT_PROBE / … |
| `aws.assetAttributes.hostname` | `src_hostname` | Inspector assessed instance |

---

### 3.6 AWS Security Hub / Config / Trusted Advisor

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `aws.finding.Title` / `aws.finding.ProductName` | `rule_name` / `app_name` | |
| `aws.finding.Compliance.Status` | `status` | PASSED / FAILED / NOT_AVAILABLE |
| `aws.finding.Compliance.SecurityControlId` | `rule_name` | CIS/NIST/PCI control ID |
| `aws.finding.RecordState` | `status` | ACTIVE / ARCHIVED |
| `aws.resourceType` | `app_category` | e.g. `"AWS::EC2::SecurityGroup"` |
| `aws.awsAccountId` | `domain` | |
| `aws.check-name` | `rule_name` | Trusted Advisor check |
| `aws.status` | `status` | ERROR / WARN / OK |
| `aws.configurationItemStatus` | `status` | Config resource state |

---

### 3.7 Office365 Audit Log

Events decoded by `office365` decoder.

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `office365.UserId` | `actor_user` | User performing the action |
| `office365.UserKey` | `actor_user` | Stable GUID fallback |
| `office365.actor` | `actor_user` | Display name variant |
| `office365.ClientIP` / `ClientIPAddress` / `ActorIpAddress` | `src_ip` | Connecting client IP |
| `office365.Operation` | `action` | Operation name (e.g. `"FileDownloaded"`, `"UserLoggedIn"`) |
| `office365.OrganizationId` / `OrganizationName` | `domain` | Tenant UUID / name |
| `office365.Workload` / `ApplicationDisplayName` / `EventSource` | `app_name` | Exchange / SharePoint / OneDrive / Teams |
| `office365.ObjectId` / `SiteUrl` / `SourceRelativeUrl` | `url` | Resource URL |
| `office365.ResultStatus` | `status` | Succeeded / Failed / PartiallySucceeded |
| `office365.InternalLogonType` | `app_category` | Exchange logon type integer (0=Owner, 1=Delegate, 2=Admin) |
| `office365.LogonType` | `app_category` | Azure AD logon type integer |
| `office365.AuthenticationType` | `app_category` | Auth protocol (FormsCookieAuth / OAuth / …) |
| `office365.DeviceDisplayName` | `dst_hostname` | Connecting device name |
| `office365.SourceFileName` / `SourceFileExtension` | `file_name` | SharePoint / OneDrive file |
| **Extensions sub-fields** | | |
| `office365.AppId` | `extensions.o365_app_id` | Application GUID |
| `office365.ClientAppId` | `extensions.o365_client_app_id` | |
| `office365.CorrelationId` | `extensions.o365_correlation_id` | Spans multiple operations |
| `office365.BrowserType` | `extensions.browser_name` | |
| `office365.ExtendedProperties[…AuthenticationMethod]` | `extensions.o365_auth_type` | MFA / password / token |
| `office365.ChatName` | `extensions.o365_chat_name` | Teams chat |
| `office365.SiteTitle` | `extensions.o365_site_title` | SharePoint site |
| `office365.TargetUsername` | `extensions.o365_target_user` | |

---

### 3.8 GCP Cloud Logging

Events decoded by `gcp-pubsub` / `gcp_pubsub` decoder. Class 4001 (Network Activity).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `gcp.protoPayload.requestMetadata.callerIp` | `src_ip` | API caller IP |
| `gcp.protoPayload.authenticationInfo.principalEmail` | `actor_user` | Service account / user email |
| `gcp.protoPayload.methodName` | `action` | e.g. `"google.iam.admin.v1.CreateRole"` |
| `gcp.protoPayload.resourceName` | `url` | GCP resource path |
| `gcp.resource.labels.project_id` | `domain` | GCP project ID |
| `gcp.resource.type` | `app_name` / `app_category` | `"gce_instance"`, `"dns_query"`, `"k8s_cluster"` |
| `gcp.bucket` | `domain` | GCS bucket name |
| `gcp.severity` | `severity` / `severity_id` | EMERGENCY/ALERT/CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG |
| `gcp.jsonPayload.sourceIP` | `src_ip` | DNS Cloud Logging source |
| `gcp.jsonPayload.responseCode` | `status` | Response code |
| `gcp.jsonPayload.statusCode` | `http_status` | HTTP status (Cloud Armor) |
| `gcp.jsonPayload.rule_details.action` | `action` | Cloud Armor / Firewall rule action |

---

### 3.9 Azure AD / Monitor

Events decoded by `azure-ad` / `azure_ad` decoder. Class 3002 (Authentication).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `azure.callerIpAddress` / `azure.properties.ipAddress` / `azure.properties.clientIP` | `src_ip` | Sign-in / operation source IP |
| `azure.properties.userPrincipalName` | `actor_user` | UPN (user@tenant.com) |
| `azure.properties.initiatedBy.user.userPrincipalName` | `actor_user` | Initiator in delegated scenarios |
| `azure.operationName` | `action` | e.g. `"Sign-in activity"` |
| `azure.properties.operationType` | `action` | Update / Add / Delete |
| `azure.resultType` | `status` | `"0"` = success, non-zero = error |
| `azure.resultDescription` | `status` | Human error description |
| `azure.tenantId` | `domain` | Azure AD tenant UUID |
| `azure.resourceType` | `app_name` | Resource type |
| `azure.properties.appDisplayName` | `app_name` | Application display name |
| `azure.properties.resourceUri` | `url` | Resource URI |

---

### 3.10 Okta System Log

Events decoded by `okta` decoder. Class 3002 (Authentication).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `okta.client.ipAddress` | `src_ip` | Client IP |
| `okta.actor.alternateId` | `actor_user` | Email-based identity (preferred) |
| `okta.actor.displayName` | `actor_user` | Display name fallback |
| `okta.displayMessage` | `action` | Human label (e.g. `"User single sign on to app"`) |
| `okta.eventType` | `action` | Machine key (e.g. `"user.session.start"`) |
| `okta.outcome.result` | `status` | SUCCESS / FAILURE / SKIPPED / ALLOW / DENY |
| `okta.client.userAgent.browser` | `app_name` | Browser / SDK name |
| `okta.target.alternateId` | `app_name` | Target app client ID |
| `okta.target.displayName` | `url` | Target resource name |

---

### 3.11 Zeek / Bro network sensor

Events decoded by `zeek` / `bro-ids` decoder. Class 4001 (Network Activity).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `zeek.id.orig_h` | `src_ip` | Originating endpoint IP |
| `zeek.id.resp_h` | `dst_ip` | Responding endpoint IP |
| `zeek.id.orig_p` | `src_port` | Originating port (numeric) |
| `zeek.id.resp_p` | `dst_port` | Responding port (numeric) |
| `zeek._path` | `interface_in` | Log path = sensor/protocol (conn, dns, http, …) |
| `zeek._path` | `app_name` | Same field — also used as service identifier |

---

### 3.12 Suricata IDS

Events decoded by `suricata` decoder. Class 4001 (Network Activity) or 4002 (HTTP Activity).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `alert.src_ip` | `src_ip` | Alert source IP |
| `alert.dest_ip` | `dst_ip` | Alert destination IP |
| `alert.src_port` | `src_port` | Alert source port |
| `alert.dest_port` | `dst_port` | Alert destination port |
| `alert.proto` | `network_protocol` | Transport protocol |
| `alert.action` | `action` | allowed / blocked |
| `rule_action` | `action` | Suricata rule disposition |

---

### 3.13 Wazuh Vulnerability Detector

Events from `vulnerability-detector` group. Class 2002 (Vulnerability Finding).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `vulnerability.cve` | `cve_id` | e.g. `"CVE-2025-61984"` |
| `vulnerability.cvss.cvss3.base_score` | `cvss_score` | Float 0.0–10.0 |
| `vulnerability.severity` | `severity` / `severity_id` | Overrides rule level |
| `vulnerability.reference` | `url` | Advisory / patch URL |
| `vulnerability.package.name` | `app_name` | Affected package |
| `vulnerability.status` | `status` | Active / Obsolete |
| `agent.name` | `device_name` | Host with vulnerable package |

---

### 3.14 Wazuh FIM (File Integrity Monitoring)

Events from `syscheck` group. Class 1001 (File System Activity).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `syscheck.path` | `file_name` | Full file path |
| `syscheck.event` | → `activity_id` | added→1, read→2, modified→3, deleted→4, renamed→5 |
| **Extensions sub-fields** | | |
| `syscheck.md5_after` | `extensions.fim_md5` | MD5 hash after change |
| `syscheck.sha1_after` | `extensions.fim_sha1` | SHA1 hash after change |
| `syscheck.sha256_after` | `extensions.fim_sha256` | SHA256 hash (preferred) |
| `syscheck.size_after` | `extensions.fim_size` | File size in bytes |
| `syscheck.mode` | `extensions.fim_mode` | scheduled / realtime / whodata |
| `syscheck.changed_attributes` | `extensions.fim_changed_attrs` | JSON list of changed attrs |

---

### 3.15 Wazuh SCA (Security Configuration Assessment)

Events from `sca` group. Class 2003 (Compliance Finding).

| Wazuh field | ClickHouse column | Notes |
|---|---|---|
| `sca.check.title` | `finding_title` | Overrides generic rule description |
| `sca.check.result` | `status` | pass / fail / not applicable |
| `sca.policy` | `app_name` | Benchmark name (e.g. `"CIS Microsoft Windows 10"`) |
| `sca.type` | `app_category` | check / policy / audit |
| **Extensions sub-fields** | | |
| `sca.scan_id` | `extensions.sca_scan_id` | Scan UUID |
| `sca.check.id` | `extensions.sca_check_id` | Check number |
| `sca.check.compliance.cis` | `extensions.sca_cis_control` | CIS control reference |
| `sca.check.compliance.cis_csc_v7` | `extensions.sca_cis_csc_v7` | CIS CSC v7 control |
| `sca.check.compliance.cis_csc_v8` | `extensions.sca_cis_csc_v8` | CIS CSC v8 control |
| `sca.check.compliance.cmmc_v2.0` | `extensions.sca_cmmc_v2` | CMMC 2.0 practice |
| `sca.check.compliance.hipaa` | `extensions.sca_hipaa` | HIPAA safeguard |
| `sca.check.compliance.iso_27001-2013` | `extensions.sca_iso_27001` | ISO 27001 control |
| `sca.check.compliance.mitre_mitigations` | `extensions.sca_mitre_mitigations` | MITRE ATT&CK mitigation ID |
| `sca.check.compliance.mitre_tactics` | `extensions.sca_mitre_tactics` | MITRE ATT&CK tactic |
| `sca.check.compliance.mitre_techniques` | `extensions.sca_mitre_techniques` | MITRE ATT&CK technique |
| `sca.check.compliance.nist_sp_800-53` | `extensions.sca_nist_800_53` | NIST SP 800-53 control |
| `sca.check.compliance.pci_dss_v3.2.1` | `extensions.sca_pci_dss_v3` | PCI DSS v3.2.1 requirement |
| `sca.check.compliance.pci_dss_v4.0` | `extensions.sca_pci_dss_v4` | PCI DSS v4.0 requirement |
| `sca.check.compliance.soc_2` | `extensions.sca_soc2` | SOC 2 criteria |
| `sca.check.command[0]` | `extensions.sca_check_command` | Audit command |
| `sca.check.file[0]` | `extensions.sca_check_file` | Audited file path |
| `sca.check.references` | `extensions.sca_references` | Check reference URL |
| `sca.check.description` | `extensions.sca_description` | Full check text |
| `sca.check.rationale` | `extensions.sca_rationale` | Why this matters |
| `sca.check.remediation` | `extensions.sca_remediation` | How to fix it |
| `sca.check.reason` | `extensions.sca_reason` | Why it failed |
| `sca.policy_id` | `extensions.sca_policy_id` | Benchmark ID slug |
| `sca.description` | `extensions.sca_policy_description` | Benchmark description |
| `sca.file` | `extensions.sca_policy_file` | Policy definition file |
| `sca.score` | `extensions.sca_score` | Overall score (0-100) |
| `sca.total_checks` | `extensions.sca_total_checks` | Total checks in scan |
| `sca.passed` | `extensions.sca_passed_count` | Passed check count |
| `sca.failed` | `extensions.sca_failed_count` | Failed check count |
| `sca.invalid` | `extensions.sca_invalid_count` | Invalid/skipped check count |

---

## 4. Extensions column key reference

The `extensions` column is a JSON string. Query with `JSONExtractString(extensions, 'key')`.

### Windows

| Key | Source field | Description |
|---|---|---|
| `win_event_id` | `win.system.eventID` | Windows Event ID (e.g. `"4624"`) |
| `win_channel` | `win.system.channel` | Log channel (`"Security"`, `"System"`, …) |
| `win_logon_type` | `win.eventdata.logonType` | Logon type integer string |
| `win_param1`–`win_param7` | `win.eventdata.param1`–`param7` | SCM/service context fields |
| `win_event_binary` | `win.eventdata.binary` | Hex-encoded raw event data |

### SCA / compliance

| Key | Source field | Description |
|---|---|---|
| `sca_scan_id` | `sca.scan_id` | Scan UUID |
| `sca_check_id` | `sca.check.id` | CIS check number |
| `sca_cis_control` | `sca.check.compliance.cis` | CIS control reference |
| `sca_cis_csc` | `sca.check.compliance.cis_csc` | CIS CSC control (legacy) |
| `sca_cis_csc_v7` | `sca.check.compliance.cis_csc_v7` | CIS CSC v7 control |
| `sca_cis_csc_v8` | `sca.check.compliance.cis_csc_v8` | CIS CSC v8 control |
| `sca_cmmc_v2` | `sca.check.compliance.cmmc_v2.0` | CMMC 2.0 practice |
| `sca_hipaa` | `sca.check.compliance.hipaa` | HIPAA safeguard |
| `sca_iso_27001` | `sca.check.compliance.iso_27001-2013` | ISO 27001 control |
| `sca_mitre_mitigations` | `sca.check.compliance.mitre_mitigations` | MITRE ATT&CK mitigation ID |
| `sca_mitre_tactics` | `sca.check.compliance.mitre_tactics` | MITRE ATT&CK tactic |
| `sca_mitre_techniques` | `sca.check.compliance.mitre_techniques` | MITRE ATT&CK technique |
| `sca_nist_800_53` | `sca.check.compliance.nist_sp_800-53` | NIST SP 800-53 control |
| `sca_pci_dss_v3` | `sca.check.compliance.pci_dss_v3.2.1` | PCI DSS v3.2.1 requirement |
| `sca_pci_dss_v4` | `sca.check.compliance.pci_dss_v4.0` | PCI DSS v4.0 requirement |
| `sca_soc2` | `sca.check.compliance.soc_2` | SOC 2 Trust Service Criteria |
| `sca_check_command` | `sca.check.command[0]` | Audit command run |
| `sca_check_file` | `sca.check.file[0]` | Audited file path |
| `sca_references` | `sca.check.references` | Check reference URL |
| `sca_description` | `sca.check.description` | Check description |
| `sca_rationale` | `sca.check.rationale` | Security rationale |
| `sca_remediation` | `sca.check.remediation` | Remediation steps |
| `sca_reason` | `sca.check.reason` | Failure reason |
| `sca_policy_id` | `sca.policy_id` | Benchmark ID slug |
| `sca_policy_description` | `sca.description` | Benchmark description |
| `sca_policy_file` | `sca.file` | Policy definition file |
| `sca_score` | `sca.score` | Overall score (0–100) |
| `sca_total_checks` | `sca.total_checks` | Total checks in scan |
| `sca_passed_count` | `sca.passed` | Passed check count |
| `sca_failed_count` | `sca.failed` | Failed check count |
| `sca_invalid_count` | `sca.invalid` | Invalid / skipped check count |

### FIM (File Integrity Monitoring)

| Key | Source field | Description |
|---|---|---|
| `fim_md5` | `syscheck.md5_after` | MD5 after change |
| `fim_sha1` | `syscheck.sha1_after` | SHA1 after change |
| `fim_sha256` | `syscheck.sha256_after` | SHA256 after change |
| `fim_size` | `syscheck.size_after` | File size |
| `fim_mode` | `syscheck.mode` | Monitoring mode |
| `fim_changed_attrs` | `syscheck.changed_attributes` | Changed attribute list (JSON) |

### Process / user context

| Key | Source field | Description |
|---|---|---|
| `actor_uid` | `data.uid` | Numeric UID |
| `actor_gid` | `data.gid` | Numeric GID |
| `actor_home_dir` | `data.home` | Home directory |
| `actor_shell` | `data.shell` | Login shell |
| `tty` | `data.tty` | Terminal device |
| `working_dir` | `data.pwd` | Working directory |
| `audit_type` | `audit.type` | auditd syscall type |
| `audit_id` | `audit.id` | auditd event ID |
| `audit_euid` | `audit.euid` | Effective UID (auditd) |
| `audit_uid` | `audit.uid` | Real UID (auditd) |
| `audit_gid` | `audit.gid` | Real GID (auditd) |
| `audit_session` | `audit.session` | Audit session ID |

### dpkg / apt packages

| Key | Source field | Description |
|---|---|---|
| `package_version` | `data.version` | Package version string |
| `package_arch` | `data.arch` | Architecture (amd64 / arm64 / …) |

### AWS CloudTrail / integrations

| Key | Source field | Description |
|---|---|---|
| `aws_event_id` | `aws.eventID` | CloudTrail event UUID |
| `aws_request_id` | `aws.requestID` | API request UUID |
| `aws_region` | `aws.awsRegion` | AWS region |
| `aws_user_agent` | `aws.userAgent` | SDK / CLI / console |
| `aws_identity_type` | `aws.userIdentity.type` | IAMUser / AssumedRole / AWSService |
| `aws_mfa_used` | `aws.additionalEventData.MFAUsed` | Yes / No |
| `aws_mfa_identifier` | `aws.additionalEventData.MFAIdentifier` | MFA device ARN |
| `aws_event_time` | `aws.eventTime` | ISO 8601 event timestamp |
| `aws_access_key_id` | `aws.userIdentity.accessKeyId` | Long-term or session key |
| `aws_session_issuer_type` | `aws.userIdentity.sessionContext.sessionIssuer.type` | Role / User |
| `aws_session_principal_id` | `aws.userIdentity.sessionContext.sessionIssuer.principalId` | Principal UUID |
| `aws_session_issuer_account` | `aws.userIdentity.sessionContext.sessionIssuer.accountId` | Owning account ID |
| `aws_session_mfa_auth` | `aws.userIdentity.sessionContext.attributes.mfaAuthenticated` | true / false |
| `aws_session_created_at` | `aws.userIdentity.sessionContext.attributes.creationDate` | Session creation time |
| `aws_federated_provider` | `aws.userIdentity.sessionContext.webIdFederationData.federatedProvider` | OIDC/SAML provider |
| `aws_req_network_interface_id` | `aws.requestParameters.networkInterfaceId` | ENI ID |
| `aws_req_security_group_id` | `aws.requestParameters.groupId` | Security group ID |
| `aws_req_subnet_id` | `aws.requestParameters.subnetId` | Subnet ID |
| `aws_req_snapshot_id` | `aws.requestParameters.snapshotId` | EBS snapshot ID |
| `aws_req_volume_id` | `aws.requestParameters.volumeId` | EBS volume ID |
| `aws_req_allocation_id` | `aws.requestParameters.allocationId` | EIP allocation ID |
| `aws_res_public_ip` | `aws.responseElements.publicIp` | Allocated public IP |
| `aws_res_network_interface_id` | `aws.responseElements.networkInterfaceId` | Returned ENI ID |
| `aws_res_allocation_id` | `aws.responseElements.allocationId` | Returned EIP allocation ID |
| `aws_res_snapshot_id` | `aws.responseElements.snapshotId` | Created snapshot ID |
| `aws_res_volume_id` | `aws.responseElements.volumeId` | Created volume ID |
| `tls_version` | `aws.tlsDetails.tlsVersion` | TLS version |
| `tls_cipher_suite` | `aws.tlsDetails.cipherSuite` | Cipher suite |
| `aws_resource_arn` | `aws.resources.ARN` | Affected resource ARN |
| `aws_error_message` | `aws.errorMessage` | API error detail |
| `aws_kms_key_id` | `aws.requestParameters.keyId` | KMS key ARN |
| `aws_log_file` | `aws.log_info.log_file` | S3 source log path |
| `aws_service_state` | `aws.serviceEventDetails.state` | |
| `aws_credential_challenge` | `aws.serviceEventDetails.CredentialChallenge` | MFA challenge type |

### Office365

| Key | Source field | Description |
|---|---|---|
| `o365_app_id` | `office365.AppId` | Application GUID |
| `o365_client_app_id` | `office365.ClientAppId` | Client application ID |
| `o365_correlation_id` | `office365.CorrelationId` | Cross-operation correlation UUID |
| `o365_auth_type` | `office365.ExtendedProperties[AuthenticationMethod]` | Auth method |
| `browser_name` | `office365.BrowserType` | Browser type string |
| `o365_chat_name` | `office365.ChatName` | Teams chat name |
| `o365_site_title` | `office365.SiteTitle` | SharePoint site title |
| `o365_target_user` | `office365.TargetUsername` | Target user |
| `o365_item_type` | `office365.ItemType` | List / Document / … |
| `o365_list_id` | `office365.ListId` | SharePoint list GUID |

---

## 5. Sample Grafana SQL queries

Replace `ocsf_my_server` with your actual table name. Use `$__timeFilter(time)` and `$__interval` for Grafana time range / auto-grouping.

### Security overview — event count by severity (time series)

```sql
SELECT
    toStartOfInterval(time, INTERVAL $__interval second) AS t,
    severity,
    count() AS events
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
GROUP BY t, severity
ORDER BY t, severity
```

### Top attacked hosts (table)

```sql
SELECT
    device_name,
    count() AS hits,
    max(wazuh_rule_level) AS max_level,
    countIf(severity_id >= 4) AS high_critical
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
GROUP BY device_name
ORDER BY hits DESC
LIMIT 20
```

### Top source IPs by hit count (table / geomap)

```sql
SELECT
    src_ip,
    count() AS attempts,
    uniq(device_name) AS targets,
    max(wazuh_rule_level) AS max_level,
    any(finding_title) AS example_rule
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND src_ip != ''
GROUP BY src_ip
ORDER BY attempts DESC
LIMIT 50
```

### Authentication failures by user and source IP (table)

```sql
SELECT
    actor_user,
    src_ip,
    count() AS failures,
    max(time) AS last_seen,
    any(finding_title) AS example
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND class_uid = 3002
  AND status_id = 2   -- Failure
GROUP BY actor_user, src_ip
ORDER BY failures DESC
LIMIT 20
```

### Brute force detection — IPs with >50 auth failures (alert table)

```sql
SELECT
    src_ip,
    actor_user,
    count() AS attempts,
    min(time) AS first_seen,
    max(time) AS last_seen
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND class_uid = 3002
  AND status_id = 2
GROUP BY src_ip, actor_user
HAVING attempts > 50
ORDER BY attempts DESC
```

### MITRE ATT&CK heatmap — tactic vs severity (heatmap)

```sql
SELECT
    attack_tactic AS tactic,
    severity,
    count() AS events
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND attack_tactic != ''
GROUP BY tactic, severity
ORDER BY tactic, severity
```

### File Integrity Monitoring — changed files (table)

```sql
SELECT
    time,
    device_name,
    file_name,
    activity_name,
    actor_user,
    JSONExtractString(extensions, 'fim_sha256') AS sha256_after,
    JSONExtractString(extensions, 'fim_changed_attrs') AS changed_attrs
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND class_uid = 1001
ORDER BY time DESC
LIMIT 100
```

### CVE vulnerability summary — by severity and affected package (table)

```sql
SELECT
    cve_id,
    app_name AS package,
    severity,
    cvss_score,
    count() AS affected_hosts,
    groupUniqArray(device_name) AS hosts,
    any(url) AS advisory_url
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND class_uid = 2002
  AND cve_id != ''
GROUP BY cve_id, package, severity, cvss_score
ORDER BY cvss_score DESC, affected_hosts DESC
LIMIT 50
```

### SCA compliance check results by policy (bar chart)

```sql
SELECT
    app_name AS benchmark,
    status,
    count() AS checks
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND class_uid = 2003
GROUP BY benchmark, status
ORDER BY benchmark, status
```

### Windows Event ID distribution (table)

```sql
SELECT
    JSONExtractString(extensions, 'win_event_id') AS event_id,
    any(finding_title) AS description,
    count() AS occurrences,
    max(wazuh_rule_level) AS max_level
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND decoder_name LIKE '%windows%'
  AND JSONExtractString(extensions, 'win_event_id') != ''
GROUP BY event_id
ORDER BY occurrences DESC
LIMIT 30
```

### AWS CloudTrail — API calls by service (pie chart)

```sql
SELECT
    app_name AS aws_service,
    count() AS calls,
    countIf(status = 'Failure' OR extensions LIKE '%aws_error%') AS errors
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND src_location LIKE '%cloudtrail%'
GROUP BY aws_service
ORDER BY calls DESC
LIMIT 15
```

### Office365 — operations by workload (bar chart)

```sql
SELECT
    app_name AS workload,
    action AS operation,
    count() AS events
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND decoder_name = 'office365'
GROUP BY workload, operation
ORDER BY workload, events DESC
```

### Network traffic top talkers (table)

```sql
SELECT
    src_ip,
    dst_ip,
    dst_port,
    network_protocol,
    sum(bytes_in) AS total_bytes_in,
    sum(bytes_out) AS total_bytes_out,
    count() AS flows
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND class_uid = 4001
  AND src_ip != ''
GROUP BY src_ip, dst_ip, dst_port, network_protocol
ORDER BY (total_bytes_in + total_bytes_out) DESC
LIMIT 20
```

### PCI DSS compliance — events matching specific requirement (table)

```sql
SELECT
    time,
    device_name,
    finding_uid,
    finding_title,
    pci_dss,
    severity,
    src_ip,
    actor_user
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
  AND pci_dss LIKE '%10.%'
ORDER BY time DESC
LIMIT 100
```

### Rule-level trending over time (time series by severity tier)

```sql
SELECT
    toStartOfInterval(time, INTERVAL $__interval second) AS t,
    countIf(wazuh_rule_level BETWEEN 10 AND 15) AS critical_high,
    countIf(wazuh_rule_level BETWEEN 7 AND 9)  AS medium,
    countIf(wazuh_rule_level BETWEEN 4 AND 6)  AS low,
    countIf(wazuh_rule_level BETWEEN 1 AND 3)  AS info
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
GROUP BY t
ORDER BY t
```

### Unique actors per day — user activity summary

```sql
SELECT
    toDate(time) AS day,
    uniq(actor_user) AS unique_users,
    count() AS total_events,
    countIf(class_uid = 3002) AS auth_events,
    countIf(class_uid = 3001) AS account_changes
FROM wazuh_ocsf.ocsf_my_server
WHERE $__timeFilter(time)
GROUP BY day
ORDER BY day
```

---

> **Grafana datasource tip:** Use the [Grafana ClickHouse plugin](https://grafana.com/grafana/plugins/grafana-clickhouse-datasource/) (`grafana-clickhouse-datasource`). Set the database to `wazuh_ocsf`. Use `time` as the time field (DateTime type) in all panels. For table variables (e.g. `$table`) use a query variable with `SHOW TABLES FROM wazuh_ocsf`.

> **Performance tip:** All typed columns have skip indexes. Filter on `class_uid`, `severity_id`, `time`, `src_ip`, `actor_user`, `finding_uid`, and `device_name` first — these hit the most indexes and reduce scan volume. Avoid `JSONExtractString(event_data, ...)` in WHERE clauses for large time ranges.
