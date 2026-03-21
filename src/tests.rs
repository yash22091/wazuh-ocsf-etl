use crate::config::CustomMappings;
use crate::pipeline::classify::{classify_event, map_severity};
use crate::pipeline::field_paths::{BYTES_IN, BYTES_OUT};
use crate::pipeline::transform::{routing_table, transform};
use crate::util::json::{
    first_port, first_str, first_u64, flatten_to_paths, get_data_field, jpath,
};
use crate::util::unmapped::{
    track_unmapped_fields, write_unmapped_report, FieldInfo, UNMAPPED_TRACKER,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

fn no_custom() -> CustomMappings {
    CustomMappings::default()
}

// ── Sanitise ─────────────────────────────────────────────────────────

#[test]
fn sanitize_path() {
    assert_eq!(
        crate::pipeline::transform::sanitize_name("/var/log/auth.log"),
        "var_log_auth_log"
    );
}
#[test]
fn sanitize_dashes_dots() {
    assert_eq!(
        crate::pipeline::transform::sanitize_name("agent-01.corp.local"),
        "agent_01_corp_local"
    );
}

// ── Routing ──────────────────────────────────────────────────────────

#[test]
fn route_default_agent_name() {
    let t = routing_table("db", "linux-srv-01", "/var/log/auth.log", &[]);
    assert_eq!(t, "db.ocsf_linux_srv_01");
}
#[test]
fn route_special_location() {
    let sp = vec!["aws-cloudtrail".to_string()];
    let t = routing_table("db", "any-agent", "aws-cloudtrail", &sp);
    assert_eq!(t, "db.ocsf_aws_cloudtrail");
}
#[test]
fn route_loc_not_in_special_uses_agent() {
    let sp = vec!["aws-cloudtrail".to_string()];
    let t = routing_table("db", "win-dc-01", "EventChannel", &sp);
    assert_eq!(t, "db.ocsf_win_dc_01");
}
#[test]
fn route_empty_agent_fallback() {
    let t = routing_table("db", "", "unknown", &[]);
    assert_eq!(t, "db.ocsf_unknown_agent");
}

// ── Severity ─────────────────────────────────────────────────────────

#[test]
fn severity_bands() {
    let cases = [
        (0, "Unknown"),
        (1, "Informational"),
        (4, "Low"),
        (7, "Medium"),
        (10, "High"),
        (13, "Critical"),
        (15, "Critical"),
    ];
    for (lvl, label) in cases {
        assert_eq!(map_severity(lvl).1, label, "level={lvl}");
    }
}
#[test]
fn severity_ids_are_valid_ocsf() {
    let valid: HashSet<u8> = [0, 1, 2, 3, 4, 5, 99].into();
    for level in 0u64..=20 {
        let (id, _) = map_severity(level);
        assert!(
            valid.contains(&id),
            "severity_id={id} for level={level} is not in OCSF 1.7.0 enum"
        );
    }
}

// ── JSON helpers ─────────────────────────────────────────────────────

#[test]
fn jpath_nested() {
    let v = serde_json::json!({"win":{"eventdata":{"ipAddress":"1.2.3.4"}}});
    assert_eq!(jpath(&v, "win.eventdata.ipAddress"), "1.2.3.4");
    assert_eq!(jpath(&v, "win.eventdata.missing"), "");
}
#[test]
fn get_data_field_literal_key() {
    let v = serde_json::json!({"audit.command": "ls"});
    assert_eq!(get_data_field(&v, "audit.command"), "ls");
}
#[test]
fn get_data_field_nested_fallback() {
    let v = serde_json::json!({"audit": {"command": "ls"}});
    assert_eq!(get_data_field(&v, "audit.command"), "ls");
}
#[test]
fn get_data_field_number_and_bool() {
    let v = serde_json::json!({"port": 8443, "retries": 3, "tls": true});
    assert_eq!(get_data_field(&v, "port"), "8443");
    assert_eq!(get_data_field(&v, "retries"), "3");
    assert_eq!(get_data_field(&v, "tls"), "true");
}
#[test]
fn get_data_field_nested_number() {
    let v = serde_json::json!({"conn": {"src_port": 12345}});
    assert_eq!(get_data_field(&v, "conn.src_port"), "12345");
}
#[test]
fn first_port_string_and_number() {
    let v = serde_json::json!({"s":"8080","n":443,"zero":"0"});
    assert_eq!(first_port(&v, &["s"]), 8080u16);
    assert_eq!(first_port(&v, &["n"]), 443u16);
    assert_eq!(first_port(&v, &["zero"]), 0u16);
}
#[test]
fn first_u64_bytes() {
    let v = serde_json::json!({"rcvdbyte": "102400", "sentbyte": 204800u64});
    assert_eq!(first_u64(&v, BYTES_IN), 102400u64);
    assert_eq!(first_u64(&v, BYTES_OUT), 204800u64);
}

// ── Syslog / generic Linux alert ─────────────────────────────────────

#[test]
fn transform_syslog() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:00:00Z",
        "agent":  {"id":"001","name":"linux-srv-01","ip":"10.0.0.1"},
        "rule":   {"id":"5503","description":"SSH brute force","level":10,
                   "groups":["syslog","sshd"],
                   "mitre":{"technique":["T1110"],"id":["T1110"],"tactic":["credential-access"]}},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"sshd"},
        "location":"/var/log/auth.log",
        "data":{"srcip":"203.0.113.5","srcport":"55123","dstport":"22",
                "srcuser":"root","protocol":"tcp"}
    }"#;
    let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(tbl, "db.ocsf_linux_srv_01");
    assert_eq!(rec.src_ip, "203.0.113.5");
    assert_eq!(rec.src_port, 55123u16);
    assert_eq!(rec.dst_port, 22u16);
    assert_eq!(rec.actor_user, "root");
    assert_eq!(rec.network_protocol, "tcp");
    assert_eq!(rec.severity_id, 4);
    assert!(rec.attack_id.contains("T1110"));
    assert_eq!(rec.decoder_name, "sshd");
}

// ── Windows Event Channel ─────────────────────────────────────────────

#[test]
fn transform_windows_eventchannel() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:00:00Z",
        "agent":  {"id":"002","name":"win-dc-01","ip":"10.0.1.5"},
        "rule":   {"id":"60106","description":"Windows login failure","level":5,
                   "groups":["windows","authentication_failed"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"windows_eventchannel"},
        "location":"EventChannel",
        "data":{
            "win":{
                "system":{"computer":"WIN-DC-01","eventID":"4625"},
                "eventdata":{
                    "ipAddress":"192.168.1.100",
                    "ipPort":"0",
                    "targetUserName":"Administrator",
                    "subjectDomainName":"CORP",
                    "workstationName":"WORKSTATION01",
                    "status":"0xC000006D"
                }
            }
        }
    }"#;
    let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(tbl, "db.ocsf_win_dc_01");
    assert_eq!(rec.src_ip, "192.168.1.100");
    assert_eq!(rec.actor_user, "Administrator");
    assert_eq!(rec.domain, "CORP");
    assert_eq!(rec.src_hostname, "WIN-DC-01");
    assert_eq!(rec.status, "0xC000006D");
    assert_eq!(rec.severity_id, 2);
}

// ── Suricata / IDS ────────────────────────────────────────────────────

#[test]
fn transform_suricata() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:05:00Z",
        "agent":  {"id":"003","name":"ids-sensor","ip":"10.0.2.1"},
        "rule":   {"id":"86601","description":"Suricata: ET SCAN","level":8,
                   "groups":["ids","suricata"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"json"},
        "location":"/var/log/suricata/eve.json",
        "data":{
            "alert":{
                "action":"blocked","src_ip":"198.51.100.7",
                "dest_ip":"10.0.2.1","src_port":12345,
                "dest_port":22,"proto":"TCP"
            },
            "bytes":1024
        }
    }"#;
    let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(tbl, "db.ocsf_ids_sensor");
    assert_eq!(rec.src_ip, "198.51.100.7");
    assert_eq!(rec.dst_port, 22u16);
    assert_eq!(rec.network_protocol, "TCP");
    assert_eq!(rec.action, "blocked");
    assert_eq!(rec.bytes_in, 1024u64);
}

// ── FortiGate firewall log ─────────────────────────────────────────────

#[test]
fn transform_fortigate() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:10:00Z",
        "agent":  {"id":"004","name":"fortinet-fw","ip":"10.0.3.1"},
        "rule":   {"id":"81600","description":"FortiGate: traffic blocked","level":7,
                   "groups":["firewall","fortigate"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"fortigate-traffic"},
        "location":"syslog",
        "data":{
            "srcip":"10.10.10.5","dstip":"8.8.8.8",
            "srcport":"49152","dstport":"443",
            "srcintf":"internal","dstintf":"wan1",
            "action":"deny",
            "proto":"tcp",
            "rcvdbyte":"0","sentbyte":"512",
            "transip":"203.0.113.1",
            "transport":"49200",
            "nat_dstip":"8.8.4.4"
        }
    }"#;
    let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(tbl, "db.ocsf_fortinet_fw");
    assert_eq!(rec.src_ip, "10.10.10.5");
    assert_eq!(rec.dst_ip, "8.8.8.8");
    assert_eq!(rec.dst_port, 443u16);
    assert_eq!(rec.nat_src_ip, "203.0.113.1");
    assert_eq!(rec.nat_src_port, 49200u16);
    assert_eq!(rec.nat_dst_ip, "8.8.4.4");
    assert_eq!(rec.interface_in, "internal");
    assert_eq!(rec.interface_out, "wan1");
    assert_eq!(rec.action, "deny");
    assert_eq!(rec.bytes_out, 512u64);
}

// ── AWS CloudTrail (via special location) ─────────────────────────────

#[test]
fn transform_aws_cloudtrail_special_loc() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:15:00Z",
        "agent":  {"id":"000","name":"wazuh-mgr","ip":"10.0.4.1"},
        "rule":   {"id":"80202","description":"AWS: Login failure","level":6,
                   "groups":["amazon","aws"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"json"},
        "location":"aws-cloudtrail",
        "data":{
            "aws":{
                "sourceIPAddress":"52.1.2.3",
                "eventName":"ConsoleLogin",
                "errorCode":"Failed authentication",
                "userIdentity":{
                    "userName":"jdoe",
                    "accountId":"123456789"
                }
            }
        }
    }"#;
    let sp = vec!["aws-cloudtrail".to_string()];
    let (tbl, rec) = transform(raw, "db", &sp, &no_custom()).unwrap();
    assert_eq!(tbl, "db.ocsf_aws_cloudtrail");
    assert_eq!(rec.src_ip, "52.1.2.3");
    assert_eq!(rec.actor_user, "jdoe");
    assert_eq!(rec.domain, "123456789");
    assert_eq!(rec.action, "ConsoleLogin");
    assert_eq!(rec.status, "Failed authentication");
}

// ── Auditd (literal dotted keys) ──────────────────────────────────────

#[test]
fn transform_auditd_nested() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:20:00Z",
        "agent":  {"id":"005","name":"audit-host","ip":"10.0.5.1"},
        "rule":   {"id":"80791","description":"Auditd: command run","level":3,
                   "groups":["audit","linux"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"auditd"},
        "location":"/var/log/audit/audit.log",
        "data":{
            "audit":{
                "command":"passwd",
                "pid":"1234",
                "auid":"root",
                "exe":"/usr/bin/passwd"
            }
        }
    }"#;
    let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(tbl, "db.ocsf_audit_host");
    assert_eq!(rec.process_name, "/usr/bin/passwd");
    assert_eq!(rec.actor_user, "root");
}

// ── Custom field mapping ──────────────────────────────────────────────

#[test]
fn transform_custom_fills_empty_src_ip() {
    let raw = r#"{
        "agent":{"id":"006","name":"myapp-host","ip":"10.0.6.1"},
        "rule": {"id":"1","description":"test","level":3},
        "data": {"myapp.client_addr":"1.2.3.4"}
    }"#;
    let mut cm = no_custom();
    cm.field_map
        .insert("myapp.client_addr".into(), "src_ip".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(rec.src_ip, "1.2.3.4");
}
#[test]
fn transform_custom_wont_override_existing_src_ip() {
    let raw = r#"{
        "agent":{"id":"007","name":"test","ip":""},
        "rule": {"id":"1","description":"t","level":3},
        "data": {"srcip":"5.5.5.5","myapp.other_ip":"9.9.9.9"}
    }"#;
    let mut cm = no_custom();
    cm.field_map
        .insert("myapp.other_ip".into(), "src_ip".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(rec.src_ip, "5.5.5.5");
}
#[test]
fn transform_custom_to_extension() {
    let raw = r#"{
        "agent":{"id":"008","name":"test","ip":""},
        "rule": {"id":"1","description":"t","level":3},
        "data": {"myapp.score":"99"}
    }"#;
    let mut cm = no_custom();
    cm.field_map
        .insert("myapp.score".into(), "threat_score".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(ext["threat_score"].as_str(), Some("99"));
}
#[test]
fn transform_custom_nat_and_network_fields() {
    let raw = r#"{
        "agent":{"id":"009","name":"nathost","ip":""},
        "rule": {"id":"1","description":"t","level":3},
        "data": {
            "vendor.nat_src":  "10.1.1.1",
            "vendor.nat_dst":  "10.2.2.2",
            "vendor.nsp":      "40000",
            "vendor.ndp":      "443",
            "vendor.iface_in": "eth0",
            "vendor.iface_out":"eth1",
            "vendor.bytes_in": "1024",
            "vendor.bytes_out":"2048",
            "vendor.proto":    "udp",
            "vendor.dst_host": "internal.corp"
        }
    }"#;
    let mut cm = no_custom();
    cm.field_map
        .insert("vendor.nat_src".into(), "nat_src_ip".into());
    cm.field_map
        .insert("vendor.nat_dst".into(), "nat_dst_ip".into());
    cm.field_map
        .insert("vendor.nsp".into(), "nat_src_port".into());
    cm.field_map
        .insert("vendor.ndp".into(), "nat_dst_port".into());
    cm.field_map
        .insert("vendor.iface_in".into(), "interface_in".into());
    cm.field_map
        .insert("vendor.iface_out".into(), "interface_out".into());
    cm.field_map
        .insert("vendor.bytes_in".into(), "bytes_in".into());
    cm.field_map
        .insert("vendor.bytes_out".into(), "bytes_out".into());
    cm.field_map
        .insert("vendor.proto".into(), "network_protocol".into());
    cm.field_map
        .insert("vendor.dst_host".into(), "dst_hostname".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(rec.nat_src_ip, "10.1.1.1", "nat_src_ip");
    assert_eq!(rec.nat_dst_ip, "10.2.2.2", "nat_dst_ip");
    assert_eq!(rec.nat_src_port, 40000u16, "nat_src_port");
    assert_eq!(rec.nat_dst_port, 443u16, "nat_dst_port");
    assert_eq!(rec.interface_in, "eth0", "interface_in");
    assert_eq!(rec.interface_out, "eth1", "interface_out");
    assert_eq!(rec.bytes_in, 1024u64, "bytes_in");
    assert_eq!(rec.bytes_out, 2048u64, "bytes_out");
    assert_eq!(rec.network_protocol, "udp", "network_protocol");
    assert_eq!(rec.dst_hostname, "internal.corp", "dst_hostname");
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert!(
        ext.as_object().unwrap().is_empty(),
        "extensions should be empty"
    );
}
#[test]
fn transform_custom_nat_wont_override_existing() {
    let raw = r#"{
        "agent":{"id":"010","name":"nathost2","ip":""},
        "rule": {"id":"1","description":"t","level":3},
        "data": {
            "protocol": "tcp",
            "vendor.proto": "udp"
        }
    }"#;
    let mut cm = no_custom();
    cm.field_map
        .insert("vendor.proto".into(), "network_protocol".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(
        rec.network_protocol, "tcp",
        "built-in should win, not custom"
    );
}
#[test]
fn transform_json_decoder_numeric_fields() {
    let raw = r#"{
        "agent":  {"id":"020","name":"myapp-json","ip":"10.0.0.20"},
        "rule":   {"id":"5001","description":"myapp event","level":4},
        "decoder":{"name":"json"},
        "data": {
            "client_ip":   "172.16.0.5",
            "server_ip":   "10.0.1.1",
            "client_port": 54321,
            "server_port": 443,
            "bytes_recv":  10240,
            "bytes_sent":  2048,
            "username":    "alice",
            "risk":        99
        }
    }"#;
    let mut cm = no_custom();
    cm.field_map.insert("client_ip".into(), "src_ip".into());
    cm.field_map.insert("server_ip".into(), "dst_ip".into());
    cm.field_map.insert("client_port".into(), "src_port".into());
    cm.field_map.insert("server_port".into(), "dst_port".into());
    cm.field_map.insert("bytes_recv".into(), "bytes_in".into());
    cm.field_map.insert("bytes_sent".into(), "bytes_out".into());
    cm.field_map.insert("username".into(), "actor_user".into());
    cm.field_map.insert("risk".into(), "risk_score".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(rec.src_ip, "172.16.0.5", "src_ip from JSON number decoder");
    assert_eq!(rec.dst_ip, "10.0.1.1", "dst_ip");
    assert_eq!(rec.src_port, 54321u16, "src_port from JSON number");
    assert_eq!(rec.dst_port, 443u16, "dst_port from JSON number");
    assert_eq!(rec.bytes_in, 10240u64, "bytes_in from JSON number");
    assert_eq!(rec.bytes_out, 2048u64, "bytes_out from JSON number");
    assert_eq!(rec.actor_user, "alice", "actor_user");
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(
        ext["risk_score"].as_str(),
        Some("99"),
        "numeric → extensions"
    );
}
#[test]
fn transform_json_decoder_nested_object() {
    let raw = r#"{
        "agent":  {"id":"021","name":"myapp-nested","ip":""},
        "rule":   {"id":"5002","description":"nested test","level":3},
        "decoder":{"name":"json"},
        "data": {
            "connection": {
                "src":  "192.0.2.10",
                "dst":  "198.51.100.1",
                "port": 8443
            },
            "auth": {
                "user":   "bob",
                "domain": "CORP"
            },
            "threat": {
                "score": 75,
                "name":  "BruteForce"
            }
        }
    }"#;
    let mut cm = no_custom();
    cm.field_map
        .insert("connection.src".into(), "src_ip".into());
    cm.field_map
        .insert("connection.dst".into(), "dst_ip".into());
    cm.field_map
        .insert("connection.port".into(), "dst_port".into());
    cm.field_map.insert("auth.user".into(), "actor_user".into());
    cm.field_map.insert("auth.domain".into(), "domain".into());
    cm.field_map
        .insert("threat.score".into(), "threat_score".into());
    cm.field_map
        .insert("threat.name".into(), "rule_name".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(rec.src_ip, "192.0.2.10", "nested src_ip");
    assert_eq!(rec.dst_ip, "198.51.100.1", "nested dst_ip");
    assert_eq!(rec.dst_port, 8443u16, "nested numeric port");
    assert_eq!(rec.actor_user, "bob", "nested actor_user");
    assert_eq!(rec.domain, "CORP", "nested domain");
    assert_eq!(rec.rule_name, "BruteForce", "nested rule_name");
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(
        ext["threat_score"].as_str(),
        Some("75"),
        "nested number → extensions"
    );
}
#[test]
fn custom_mappings_full_toml_roundtrip() {
    let toml_content = r#"
[meta]
ocsf_version = "1.7.0"

[field_mappings]
"myapp.client_addr"  = "src_ip"
"myapp.server_addr"  = "dst_ip"
"myapp.current_user" = "actor_user"
"myapp.risk_score"   = "vendor_risk_score"
"myapp.proto"        = "network_protocol"
"myapp.nat_ip"       = "nat_src_ip"
"myapp.iface"        = "interface_in"
"myapp.brecv"        = "bytes_in"
"myapp.bsent"        = "bytes_out"
"myapp.dst_h"        = "dst_hostname"
"#;
    let tmp = std::env::temp_dir().join("test_field_mappings_roundtrip.toml");
    std::fs::write(&tmp, toml_content).unwrap();
    let cm = CustomMappings::load(&tmp).expect("TOML must parse");

    assert_eq!(cm.ocsf_version, "1.7.0");
    assert_eq!(
        cm.field_map.get("myapp.client_addr").map(String::as_str),
        Some("src_ip")
    );
    assert_eq!(
        cm.field_map.get("myapp.server_addr").map(String::as_str),
        Some("dst_ip")
    );
    assert_eq!(
        cm.field_map.get("myapp.current_user").map(String::as_str),
        Some("actor_user")
    );
    assert_eq!(
        cm.field_map.get("myapp.risk_score").map(String::as_str),
        Some("vendor_risk_score")
    );

    let raw = r#"{
        "agent":{"id":"011","name":"myapp-server","ip":"10.0.0.1"},
        "rule": {"id":"100","description":"myapp event","level":5},
        "data": {
            "myapp.client_addr":  "192.168.1.50",
            "myapp.server_addr":  "10.0.0.5",
            "myapp.current_user": "alice",
            "myapp.risk_score":   "87",
            "myapp.proto":        "udp",
            "myapp.nat_ip":       "203.0.113.1",
            "myapp.iface":        "eth0",
            "myapp.brecv":        "1024",
            "myapp.bsent":        "2048",
            "myapp.dst_h":        "backend.corp"
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(rec.src_ip, "192.168.1.50", "src_ip");
    assert_eq!(rec.dst_ip, "10.0.0.5", "dst_ip");
    assert_eq!(rec.actor_user, "alice", "actor_user");
    assert_eq!(rec.network_protocol, "udp", "network_protocol");
    assert_eq!(rec.nat_src_ip, "203.0.113.1", "nat_src_ip");
    assert_eq!(rec.interface_in, "eth0", "interface_in");
    assert_eq!(rec.bytes_in, 1024u64, "bytes_in");
    assert_eq!(rec.bytes_out, 2048u64, "bytes_out");
    assert_eq!(rec.dst_hostname, "backend.corp", "dst_hostname");
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(ext["vendor_risk_score"].as_str(), Some("87"), "extension");

    std::fs::remove_file(&tmp).ok();
}

// ── Lossless: event_data + unmapped ───────────────────────────────────

#[test]
fn transform_zero_data_loss() {
    let raw = r#"{
        "agent":          {"id":"009","name":"test","ip":""},
        "rule":           {"id":"1","description":"t","level":3},
        "custom_toplevel":"should_be_in_unmapped",
        "data":           {"known_field":"val","extra_data":"extra"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
    assert!(
        u.get("custom_toplevel").is_some(),
        "missing custom_toplevel"
    );
    assert!(rec.event_data.contains("known_field"));
    assert!(rec.event_data.contains("extra_data"));
}
#[test]
fn transform_invalid_json_returns_none() {
    assert!(transform("{{{bad", "db", &[], &no_custom()).is_none());
}
#[test]
fn transform_missing_timestamp_fallback() {
    let raw = r#"{"rule":{"id":"1","description":"t","level":3}}"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert!(rec.time > 0);
}

// ── OCSF classify_event ───────────────────────────────────────────────

#[test]
fn classify_sshd_is_authentication() {
    let c = classify_event(
        &["sshd", "authentication_failed"],
        "sshd",
        "/var/log/auth.log",
    );
    assert_eq!(c.class_uid, 3002);
    assert_eq!(c.class_name, "Authentication");
    assert_eq!(c.category_uid, 3);
}
#[test]
fn classify_pam_is_authentication() {
    let c = classify_event(&["pam"], "pam", "/var/log/syslog");
    assert_eq!(c.class_uid, 3002);
}
#[test]
fn classify_syscheck_is_file_activity() {
    let c = classify_event(&["syscheck", "syscheck_file"], "syscheck_file", "syscheck");
    assert_eq!(c.class_uid, 1001);
    assert_eq!(c.class_name, "File System Activity");
}
#[test]
fn classify_sysmon_process_is_process_activity() {
    let c = classify_event(
        &["sysmon", "sysmon_process", "process_creation"],
        "sysmon",
        "EventChannel",
    );
    assert_eq!(c.class_uid, 1006);
    assert_eq!(c.class_name, "Process Activity");
}
#[test]
fn classify_vuln_detector() {
    let c = classify_event(&["vulnerability-detector"], "vulnerability-detector", "");
    assert_eq!(c.class_uid, 2002);
    assert_eq!(c.class_name, "Vulnerability Finding");
}
#[test]
fn classify_sca_is_compliance() {
    let c = classify_event(&["sca"], "sca", "");
    assert_eq!(c.class_uid, 2003);
    assert_eq!(c.class_name, "Compliance Finding");
}
#[test]
fn classify_adduser_is_account_change() {
    let c = classify_event(&["adduser", "linux_account"], "adduser", "");
    assert_eq!(c.class_uid, 3001);
    assert_eq!(c.class_name, "Account Change");
}
#[test]
fn classify_nginx_is_http() {
    let c = classify_event(&["web", "web-log"], "nginx", "/var/log/nginx/access.log");
    assert_eq!(c.class_uid, 4002);
    assert_eq!(c.class_name, "HTTP Activity");
}
#[test]
fn classify_access_log_location_is_http() {
    let c = classify_event(&["syslog"], "json", "/srv/app/access.log");
    assert_eq!(c.class_uid, 4002);
}
#[test]
fn classify_fortigate_is_network() {
    let c = classify_event(&["firewall", "fortigate"], "fortigate-traffic", "syslog");
    assert_eq!(c.class_uid, 4001);
    assert_eq!(c.class_name, "Network Activity");
}
#[test]
fn classify_suricata_is_network() {
    let c = classify_event(&["ids", "suricata"], "json", "/var/log/suricata/eve.json");
    assert_eq!(c.class_uid, 4001);
}
#[test]
fn classify_dns_query() {
    let c = classify_event(&["dns"], "named", "");
    assert_eq!(c.class_uid, 4003);
    assert_eq!(c.class_name, "DNS Activity");
}
#[test]
fn classify_dhcp() {
    let c = classify_event(&["dhcp"], "dhcpd", "");
    assert_eq!(c.class_uid, 4004);
}
#[test]
fn classify_default_is_detection_finding() {
    let c = classify_event(&["rootkit", "windows"], "rootcheck", "");
    assert_eq!(c.class_uid, 2004);
    assert_eq!(c.class_name, "Detection Finding");
}

// ── cloud source routing ─────────────────────────────────────────────

#[test]
fn classify_vpcflow_decoder_is_network_activity() {
    let c = classify_event(&[], "aws-vpcflow", "");
    assert_eq!(c.class_uid, 4001);
    assert_eq!(c.class_name, "Network Activity");
}
#[test]
fn classify_vpcflow_hyphen_variant() {
    let c = classify_event(&[], "vpc-flow-logs", "");
    assert_eq!(c.class_uid, 4001);
}
#[test]
fn classify_guardduty_decoder_is_vulnerability_finding() {
    let c = classify_event(&[], "aws-guardduty", "");
    assert_eq!(c.class_uid, 2002);
    assert_eq!(c.class_name, "Vulnerability Finding");
}
#[test]
fn classify_guardduty_group_is_vulnerability_finding() {
    let c = classify_event(&["amazon-guardduty"], "json", "");
    assert_eq!(c.class_uid, 2002);
}
#[test]
fn classify_okta_decoder_is_authentication() {
    let c = classify_event(&[], "okta", "");
    assert_eq!(c.class_uid, 3002);
    assert_eq!(c.class_name, "Authentication");
}
#[test]
fn classify_okta_group_is_authentication() {
    let c = classify_event(&["okta"], "json", "");
    assert_eq!(c.class_uid, 3002);
}
#[test]
fn classify_azure_ad_decoder_is_authentication() {
    let c = classify_event(&[], "azure-ad", "");
    assert_eq!(c.class_uid, 3002);
    assert_eq!(c.class_name, "Authentication");
}
#[test]
fn classify_azure_ad_underscore_is_authentication() {
    let c = classify_event(&[], "azure_ad", "");
    assert_eq!(c.class_uid, 3002);
}
#[test]
fn classify_zeek_decoder_is_network_activity() {
    let c = classify_event(&[], "zeek", "");
    assert_eq!(c.class_uid, 4001);
    assert_eq!(c.class_name, "Network Activity");
}
#[test]
fn classify_bro_group_is_network_activity() {
    let c = classify_event(&["bro"], "bro-ids", "");
    assert_eq!(c.class_uid, 4001);
}
#[test]
fn classify_cloudtrail_iam_is_authentication() {
    let c = classify_event(&["aws_iam"], "aws-cloudtrail", "");
    assert_eq!(c.class_uid, 3002);
    assert_eq!(c.class_name, "Authentication");
}

// ── class_uid in transform round-trips ───────────────────────────────

#[test]
fn transform_syslog_has_auth_class() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:00:00Z",
        "agent":  {"id":"001","name":"linux-srv","ip":"10.0.0.1"},
        "rule":   {"id":"5503","description":"SSH brute","level":10,
                   "groups":["syslog","sshd","authentication_failed"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"sshd"},
        "location":"/var/log/auth.log"
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 3002);
    assert_eq!(rec.class_name, "Authentication");
    assert_eq!(rec.category_uid, 3);
    assert_eq!(rec.category_name, "Identity & Access Management");
}
#[test]
fn transform_suricata_has_network_class() {
    let raw = r#"{
        "@timestamp":"2024-03-01T12:00:00Z",
        "agent":  {"id":"002","name":"ids","ip":"10.0.0.2"},
        "rule":   {"id":"86600","description":"IDS alert","level":7,
                   "groups":["ids","suricata"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"json"},
        "location":"/var/log/suricata/eve.json"
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4001);
    assert_eq!(rec.category_uid, 4);
}

// ── OCSF activity_id correctness per class ───────────────────────────

#[test]
fn type_uid_is_class_times_100_plus_activity() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"1","description":"t","level":3,"groups":["sshd","authentication_failed"]},
        "decoder":{"name":"sshd"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 3002);
    assert_eq!(rec.activity_id, 1, "Logon = 1");
    assert_eq!(rec.activity_name, "Logon");
    assert_eq!(
        rec.type_uid,
        3002 * 100 + 1,
        "type_uid must be class_uid*100+activity_id"
    );
}
#[test]
fn network_activity_allow_maps_to_open() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"fw","ip":""},
        "rule":{"id":"1","description":"t","level":3,"groups":["firewall","fortigate"]},
        "decoder":{"name":"fortigate-traffic"},
        "data":{"srcip":"1.2.3.4","action":"allow"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4001);
    assert_eq!(rec.activity_id, 1, "allow → Open(1)");
    assert_eq!(rec.activity_name, "Open");
    assert_eq!(rec.type_uid, 400101);
}
#[test]
fn network_activity_deny_maps_to_refuse() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"fw","ip":""},
        "rule":{"id":"1","description":"t","level":3,"groups":["firewall","fortigate"]},
        "decoder":{"name":"fortigate-traffic"},
        "data":{"srcip":"1.2.3.4","action":"deny"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 5, "deny → Refuse(5)");
    assert_eq!(rec.activity_name, "Refuse");
    assert_eq!(rec.type_uid, 400105);
}
#[test]
fn network_activity_no_action_is_traffic() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"fw","ip":""},
        "rule":{"id":"1","description":"t","level":3,"groups":["firewall","iptables"]},
        "decoder":{"name":"iptables"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4001);
    assert_eq!(rec.activity_id, 6, "no action → Traffic(6)");
    assert_eq!(rec.activity_name, "Traffic");
}
#[test]
fn dhcp_activity_id_is_assign() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"dhcp-srv","ip":""},
        "rule":{"id":"1","description":"t","level":3,"groups":["dhcp"]},
        "decoder":{"name":"dhcpd"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4004);
    assert_eq!(rec.activity_id, 1, "DHCP default → Assign(1)");
    assert_eq!(rec.activity_name, "Assign");
    assert_eq!(rec.type_uid, 400401);
}
#[test]
fn fim_added_is_create() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"550","description":"FIM","level":7,"groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "syscheck":{"event":"added","path":"/etc/passwd"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 1001);
    assert_eq!(rec.activity_id, 1, "added → Create(1)");
    assert_eq!(rec.activity_name, "Create");
}
#[test]
fn fim_modified_is_update() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"550","description":"FIM","level":7,"groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "syscheck":{"event":"modified","path":"/etc/passwd"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 3, "modified → Update(3)");
    assert_eq!(rec.activity_name, "Update");
    assert_eq!(rec.type_uid, 100103);
}
#[test]
fn fim_deleted_is_delete() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"553","description":"FIM","level":7,"groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "syscheck":{"event":"deleted","path":"/etc/passwd"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 4, "deleted → Delete(4)");
    assert_eq!(rec.activity_name, "Delete");
}
#[test]
fn account_change_group_delete() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"1","description":"group deleted","level":3,
                "groups":["adduser","groupdel"]},
        "decoder":{"name":"groupdel"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 3001);
    assert_eq!(
        rec.activity_id, 8,
        "groupdel → Delete Group(8), not Delete User(2)"
    );
    assert_eq!(rec.activity_name, "Delete Group");
}
#[test]
fn account_change_group_create() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"1","description":"group added","level":3,
                "groups":["adduser","addgroup"]},
        "decoder":{"name":"addgroup"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 7, "addgroup → Create Group(7)");
    assert_eq!(rec.activity_name, "Create Group");
}

// ── Literal dotted key lookup ─────────────────────────────────────────

#[test]
fn first_str_prefers_literal_key() {
    let flat = serde_json::json!({"audit.exe": "/bin/bash"});
    assert_eq!(first_str(&flat, &["audit.exe"]), "/bin/bash");
}
#[test]
fn first_str_nested_fallback() {
    let nested = serde_json::json!({"audit": {"exe": "/bin/bash"}});
    assert_eq!(first_str(&nested, &["audit.exe"]), "/bin/bash");
}
#[test]
fn first_port_literal_key() {
    let flat = serde_json::json!({"audit.pid": "4321"});
    assert_eq!(first_port(&flat, &["audit.pid"]), 4321u16);
}
#[test]
fn first_u64_literal_key() {
    let flat = serde_json::json!({"rcvdbyte": "2048"});
    assert_eq!(first_u64(&flat, &["rcvdbyte"]), 2048u64);
}

// ── flatten_to_paths tests ────────────────────────────────────────────

#[test]
fn flatten_flat_object() {
    let v = serde_json::json!({"a": "1", "b": "2"});
    let mut out = vec![];
    flatten_to_paths(&v, "", &mut out);
    out.sort();
    assert_eq!(
        out,
        vec![("a".into(), "1".into()), ("b".into(), "2".into())]
    );
}
#[test]
fn flatten_nested_object() {
    let v = serde_json::json!({"a": {"b": {"c": "deep"}}});
    let mut out = vec![];
    flatten_to_paths(&v, "", &mut out);
    assert_eq!(out, vec![("a.b.c".into(), "deep".into())]);
}
#[test]
fn flatten_numeric_leaf() {
    let v = serde_json::json!({"port": 443});
    let mut out = vec![];
    flatten_to_paths(&v, "", &mut out);
    assert_eq!(out, vec![("port".into(), "443".into())]);
}
#[test]
fn flatten_bool_leaf() {
    let v = serde_json::json!({"enabled": true});
    let mut out = vec![];
    flatten_to_paths(&v, "", &mut out);
    assert_eq!(out, vec![("enabled".into(), "true".into())]);
}
#[test]
fn flatten_skips_null() {
    let v = serde_json::json!({"a": null, "b": "ok"});
    let mut out = vec![];
    flatten_to_paths(&v, "", &mut out);
    assert_eq!(out, vec![("b".into(), "ok".into())]);
}

// ── track_unmapped_fields tests ───────────────────────────────────────

#[test]
fn unmapped_known_path_not_recorded() {
    let snapshot_before: HashMap<String, FieldInfo> = {
        let g = UNMAPPED_TRACKER.lock().unwrap();
        g.clone()
    };
    let data = serde_json::json!({"srcip": "1.2.3.4"});
    track_unmapped_fields(&data, &no_custom());
    let snapshot_after: HashMap<String, FieldInfo> = {
        let g = UNMAPPED_TRACKER.lock().unwrap();
        g.clone()
    };
    let new_keys: HashSet<&String> = snapshot_after
        .keys()
        .filter(|k| !snapshot_before.contains_key(*k))
        .collect();
    assert!(
        !new_keys.contains(&"srcip".to_string()),
        "srcip is a KNOWN_PATH and must not be recorded as unmapped"
    );
}
#[test]
fn unmapped_unknown_path_is_recorded() {
    let before_count = UNMAPPED_TRACKER
        .lock()
        .unwrap()
        .get("my_custom_widget")
        .map(|f| f.count)
        .unwrap_or(0);
    let data = serde_json::json!({"my_custom_widget": "xyz"});
    track_unmapped_fields(&data, &no_custom());
    let after_count = UNMAPPED_TRACKER
        .lock()
        .unwrap()
        .get("my_custom_widget")
        .map(|f| f.count)
        .unwrap_or(0);
    assert_eq!(
        after_count,
        before_count + 1,
        "unknown field must be recorded in UNMAPPED_TRACKER"
    );
}
#[test]
fn unmapped_custom_mapped_field_not_recorded() {
    let field = "my_mapped_field_xyz";
    let mut cm = no_custom();
    cm.field_map.insert(field.to_string(), "src_ip".to_string());
    let before = UNMAPPED_TRACKER
        .lock()
        .unwrap()
        .get(field)
        .map(|f| f.count)
        .unwrap_or(0);
    let data = serde_json::json!({"my_mapped_field_xyz": "10.0.0.1"});
    track_unmapped_fields(&data, &cm);
    let after = UNMAPPED_TRACKER
        .lock()
        .unwrap()
        .get(field)
        .map(|f| f.count)
        .unwrap_or(0);
    assert_eq!(
        after, before,
        "custom-mapped field must not appear in unmapped tracker"
    );
}
#[test]
fn unmapped_nested_unknown_path_is_recorded() {
    let key = "vendor.info.extra_field_abc123";
    let before = UNMAPPED_TRACKER
        .lock()
        .unwrap()
        .get(key)
        .map(|f| f.count)
        .unwrap_or(0);
    let data = serde_json::json!({"vendor": {"info": {"extra_field_abc123": "v"}}});
    track_unmapped_fields(&data, &no_custom());
    let after = UNMAPPED_TRACKER
        .lock()
        .unwrap()
        .get(key)
        .map(|f| f.count)
        .unwrap_or(0);
    assert_eq!(after, before + 1);
}
#[test]
fn write_unmapped_report_creates_valid_json() {
    {
        let mut g = UNMAPPED_TRACKER.lock().unwrap();
        g.insert(
            "test_write_field".to_string(),
            FieldInfo {
                count: 7,
                example: "hello".to_string(),
            },
        );
    }
    let tmp = std::env::temp_dir().join("wazuh_ocsf_unmapped_test.json");
    write_unmapped_report(&tmp);
    let txt = std::fs::read_to_string(&tmp).expect("report file must exist");
    let v: Value = serde_json::from_str(&txt).expect("must be valid JSON");
    assert!(v.get("fields").is_some(), "must have 'fields' key");
    assert!(
        v["fields"]
            .as_array()
            .map(|a| a.iter().any(|e| e.as_str() == Some("test_write_field")))
            .unwrap_or(false),
        "test_write_field must appear in report"
    );
    let _ = std::fs::remove_file(&tmp);
}

// ── Cloud / JSON-decoder source integration tests ────────────────────

#[test]
fn transform_vpcflow_fields() {
    let raw = r#"{
        "@timestamp":"2024-05-01T10:00:00Z",
        "agent":{"id":"010","name":"aws-agent","ip":""},
        "rule":{"id":"87001","description":"VPC Flow","level":3,"groups":["amazon-vpcflow"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"aws-vpcflow"},
        "location":"aws-vpcflow",
        "data":{
            "srcAddr":"10.1.2.3",
            "dstAddr":"10.4.5.6",
            "srcPort":54321,
            "dstPort":443,
            "protocol":"6",
            "bytes":2048,
            "packets":12,
            "interfaceId":"eni-abc123",
            "action":"ACCEPT"
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4001, "VPC Flow must be Network Activity");
    assert_eq!(rec.src_ip, "10.1.2.3");
    assert_eq!(rec.dst_ip, "10.4.5.6");
    assert_eq!(rec.src_port, 54321u16);
    assert_eq!(rec.dst_port, 443u16);
    assert_eq!(rec.bytes_in, 2048u64);
    assert_eq!(rec.action, "ACCEPT");
}
#[test]
fn transform_guardduty_nested_ip() {
    let raw = r#"{
        "@timestamp":"2024-05-02T11:00:00Z",
        "agent":{"id":"011","name":"aws-agent","ip":""},
        "rule":{"id":"87100","description":"GuardDuty","level":10,"groups":["amazon-guardduty"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"aws-guardduty"},
        "location":"aws-guardduty",
        "data":{
            "aws":{
                "service":{
                    "action":{
                        "networkConnectionAction":{
                            "remoteIpDetails":{"ipAddressV4":"198.51.100.7"},
                            "remotePortDetails":{"port":4444},
                            "localIpDetails":{"ipAddressV4":"172.16.0.5"},
                            "localPortDetails":{"port":443}
                        }
                    }
                },
                "title":"UnauthorizedAccess:EC2/SSHBruteForce"
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(
        rec.class_uid, 2002,
        "GuardDuty must be Vulnerability Finding"
    );
    assert_eq!(rec.src_ip, "198.51.100.7");
    assert_eq!(rec.dst_ip, "172.16.0.5");
    assert_eq!(rec.src_port, 4444u16);
    assert_eq!(rec.dst_port, 443u16);
}
#[test]
fn transform_okta_auth_event() {
    let raw = r#"{
        "@timestamp":"2024-05-03T09:00:00Z",
        "agent":{"id":"012","name":"okta-agent","ip":""},
        "rule":{"id":"92000","description":"Okta login","level":5,"groups":["okta"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"okta"},
        "location":"okta",
        "data":{
            "okta":{
                "actor":{
                    "alternateId":"alice@example.com",
                    "displayName":"Alice"
                },
                "client":{"ipAddress":"203.0.113.42"},
                "outcome":{"result":"SUCCESS"},
                "displayMessage":"User login to Okta",
                "eventType":"user.session.start"
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 3002, "Okta must be Authentication");
    assert_eq!(rec.src_ip, "203.0.113.42");
    assert_eq!(rec.actor_user, "alice@example.com");
    assert_eq!(rec.status, "SUCCESS");
    assert_eq!(rec.action, "User login to Okta");
}
#[test]
fn transform_azure_ad_signin() {
    let raw = r#"{
        "@timestamp":"2024-05-04T08:00:00Z",
        "agent":{"id":"013","name":"azure-agent","ip":""},
        "rule":{"id":"93000","description":"Azure AD","level":5,"groups":["azure-ad"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"azure-ad"},
        "location":"azure-ad",
        "data":{
            "azure":{
                "callerIpAddress":"203.0.113.99",
                "operationName":"Sign-in activity",
                "resultType":"0",
                "properties":{
                    "userPrincipalName":"bob@corp.onmicrosoft.com"
                }
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 3002, "Azure AD must be Authentication");
    assert_eq!(rec.src_ip, "203.0.113.99");
    assert_eq!(rec.actor_user, "bob@corp.onmicrosoft.com");
    assert_eq!(rec.action, "Sign-in activity");
    assert_eq!(rec.status, "0");
}
#[test]
fn transform_zeek_conn_log() {
    let raw = r#"{
        "@timestamp":"2024-05-05T07:00:00Z",
        "agent":{"id":"014","name":"zeek-node","ip":""},
        "rule":{"id":"94000","description":"Zeek conn","level":3,"groups":["zeek"]},
        "manager":{"name":"mgr"},
        "decoder":{"name":"zeek"},
        "location":"zeek",
        "data":{
            "zeek":{
                "_path":"conn",
                "id":{
                    "orig_h":"192.168.1.10",
                    "orig_p":52000,
                    "resp_h":"93.184.216.34",
                    "resp_p":80
                }
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4001, "Zeek conn must be Network Activity");
    assert_eq!(rec.src_ip, "192.168.1.10");
    assert_eq!(rec.dst_ip, "93.184.216.34");
    assert_eq!(rec.src_port, 52000u16);
    assert_eq!(rec.dst_port, 80u16);
}

// ── syscheck / FIM: top-level section handling ────────────────────────

#[test]
fn transform_fim_path_extracted_to_file_name() {
    // syscheck.path must be extracted to file_name (was missing — BUG FIX)
    let raw = r#"{
        "@timestamp":"2026-03-13T07:00:00Z",
        "agent":  {"id":"001","name":"linux-srv","ip":"10.0.0.1"},
        "rule":   {"id":"550","description":"Integrity check","level":7,
                   "groups":["syscheck","syscheck_file"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"syscheck"},
        "location":"syscheck",
        "full_log":"File '/etc/passwd' modified\nMode: scheduled",
        "syscheck":{
            "event":      "modified",
            "path":       "/etc/passwd",
            "md5_after":  "abc123",
            "sha1_after": "def456",
            "sha256_after":"ghi789",
            "size_after": "1234",
            "mode":       "scheduled",
            "changed_attributes":["md5","sha1","sha256"]
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 1001, "must be File System Activity");
    assert_eq!(rec.activity_id, 3, "modified → Update(3)");
    assert_eq!(
        rec.file_name, "/etc/passwd",
        "syscheck.path must land in file_name"
    );

    // hashes extracted to extensions
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(
        ext["fim_md5"].as_str(),
        Some("abc123"),
        "fim_md5 in extensions"
    );
    assert_eq!(
        ext["fim_sha1"].as_str(),
        Some("def456"),
        "fim_sha1 in extensions"
    );
    assert_eq!(
        ext["fim_sha256"].as_str(),
        Some("ghi789"),
        "fim_sha256 in extensions"
    );
    assert_eq!(
        ext["fim_size"].as_str(),
        Some("1234"),
        "fim_size in extensions"
    );
    assert_eq!(
        ext["fim_mode"].as_str(),
        Some("scheduled"),
        "fim_mode in extensions"
    );
    assert!(
        ext["fim_changed_attrs"].is_string(),
        "fim_changed_attrs in extensions"
    );

    // syscheck must NOT appear in unmapped (was leaking — BUG FIX)
    let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
    assert!(
        u.get("syscheck").is_none(),
        "syscheck must NOT be in unmapped"
    );
    assert!(
        u.get("full_log").is_none(),
        "full_log must NOT be in unmapped"
    );
}

#[test]
fn transform_fim_added_path_extracted() {
    let raw = r#"{
        "@timestamp":"2026-03-13T08:00:00Z",
        "agent":  {"id":"001","name":"host","ip":""},
        "rule":   {"id":"554","description":"FIM added","level":7,
                   "groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "syscheck":{"event":"added","path":"/tmp/malware.sh","mode":"realtime"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.file_name, "/tmp/malware.sh", "path from syscheck.path");
    assert_eq!(rec.activity_id, 1, "added → Create(1)");
    let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(
        ext["fim_mode"].as_str(),
        Some("realtime"),
        "fim_mode in extensions"
    );
}

#[test]
fn transform_fim_data_file_name_wins_over_syscheck() {
    // If data.file_name is already set (custom mapping), syscheck.path must NOT override it
    let raw = r#"{
        "@timestamp":"2026-03-13T09:00:00Z",
        "agent":  {"id":"001","name":"host","ip":""},
        "rule":   {"id":"550","description":"FIM","level":7,
                   "groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "data":    {"filename":"/data/from_data_section"},
        "syscheck":{"event":"modified","path":"/syscheck/path"}
    }"#;
    let mut cm = no_custom();
    cm.field_map.insert("filename".into(), "file_name".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(
        rec.file_name, "/data/from_data_section",
        "data section wins over syscheck.path"
    );
}

// ── predecoder extraction ─────────────────────────────────────────────

#[test]
fn transform_predecoder_hostname_fills_src_hostname() {
    // predecoder.hostname → src_hostname when not already set (was missing — BUG FIX)
    let raw = r#"{
        "@timestamp":"2026-03-13T10:00:00Z",
        "agent":  {"id":"001","name":"linux-srv","ip":"10.0.0.1"},
        "rule":   {"id":"5503","description":"SSH auth","level":5,
                   "groups":["syslog","sshd"]},
        "decoder":{"name":"sshd"},
        "predecoder":{
            "hostname":     "webserver01.corp.local",
            "program_name": "sshd",
            "timestamp":    "Mar 13 10:00:00"
        },
        "full_log":"Mar 13 10:00:00 webserver01.corp.local sshd[1234]: Failed password"
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(
        rec.src_hostname, "webserver01.corp.local",
        "predecoder.hostname must populate src_hostname"
    );
    assert_eq!(
        rec.app_name, "sshd",
        "predecoder.program_name must populate app_name"
    );

    // predecoder must NOT appear in unmapped (was leaking — BUG FIX)
    let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
    assert!(
        u.get("predecoder").is_none(),
        "predecoder must NOT be in unmapped"
    );
    assert!(
        u.get("full_log").is_none(),
        "full_log must NOT be in unmapped"
    );
}

#[test]
fn transform_predecoder_src_hostname_not_overridden() {
    // If data.* already set src_hostname, predecoder must not override it
    let raw = r#"{
        "@timestamp":"2026-03-13T11:00:00Z",
        "agent":  {"id":"001","name":"host","ip":""},
        "rule":   {"id":"1","description":"test","level":3},
        "decoder":{"name":"json"},
        "data":    {"srchost":"actual-source.corp"},
        "predecoder":{"hostname":"log-forwarder.corp","program_name":"myapp"}
    }"#;
    let mut cm = no_custom();
    cm.field_map.insert("srchost".into(), "src_hostname".into());
    let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
    assert_eq!(
        rec.src_hostname, "actual-source.corp",
        "data-derived src_hostname wins over predecoder.hostname"
    );
}

#[test]
fn transform_previous_output_not_in_unmapped() {
    // previous_output and previous_log must not appear in unmapped
    let raw = r#"{
        "@timestamp":"2026-03-13T12:00:00Z",
        "agent":  {"id":"001","name":"host","ip":""},
        "rule":   {"id":"1","description":"test","level":3},
        "decoder":{"name":"syslog"},
        "previous_output": "previous alert text",
        "previous_log":    "previous raw log line"
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
    assert!(
        u.get("previous_output").is_none(),
        "previous_output must NOT be in unmapped"
    );
    assert!(
        u.get("previous_log").is_none(),
        "previous_log must NOT be in unmapped"
    );
    // But truly unknown top-level keys still must appear
}

#[test]
fn transform_truly_unknown_toplevel_still_captured() {
    // A completely novel top-level key still ends up in unmapped
    let raw = r#"{
        "@timestamp":"2026-03-13T13:00:00Z",
        "agent":  {"id":"001","name":"host","ip":""},
        "rule":   {"id":"1","description":"test","level":3},
        "decoder":{"name":"syslog"},
        "custom_vendor_extension": {"score": 99, "flag": true}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
    assert!(
        u.get("custom_vendor_extension").is_some(),
        "unknown top-level key must still be captured in unmapped"
    );
}

// ── OCSF 1.7.0 schema validator unit tests ────────────────────────────

#[test]
fn ocsf_validator_passes_on_valid_record() {
    let raw = r#"{
        "@timestamp":"2024-01-01T00:00:00Z",
        "agent":{"id":"1","name":"host","ip":""},
        "rule":{"id":"5503","description":"SSH failed","level":10,
                "groups":["sshd","authentication_failed"]},
        "decoder":{"name":"sshd"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    let violations = crate::pipeline::validator::validate_ocsf_record(&rec);
    assert!(
        violations.is_empty(),
        "valid sshd auth record must have 0 OCSF violations, got: {violations:?}"
    );
}

#[test]
fn ocsf_validator_all_classes_produce_zero_violations() {
    // Every classifier path must produce a schema-valid record
    let test_cases: &[(&str, &str)] = &[
        // (rule groups JSON array, decoder)
        (r#"["syscheck","syscheck_file"]"#, "syscheck"),
        (
            r#"["sysmon","sysmon_process","process_creation"]"#,
            "sysmon",
        ),
        (r#"["vulnerability-detector"]"#, "vulnerability-detector"),
        (r#"["sca"]"#, "sca"),
        (r#"["adduser","linux_account"]"#, "adduser"),
        (r#"["sshd","authentication_failed"]"#, "sshd"),
        (r#"["firewall","fortigate"]"#, "fortigate-traffic"),
        (r#"["web","web-log"]"#, "nginx"),
        (r#"["dns"]"#, "named"),
        (r#"["dhcp"]"#, "dhcpd"),
        (r#"["rootkit"]"#, "rootcheck"),
        (r#"["amazon-vpcflow"]"#, "aws-vpcflow"),
        (r#"["amazon-guardduty"]"#, "aws-guardduty"),
        (r#"["okta"]"#, "okta"),
        (r#"["zeek"]"#, "zeek"),
    ];
    for (groups_json, decoder) in test_cases {
        let raw = format!(
            r#"{{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{{"id":"1","name":"host","ip":""}},
            "rule":{{"id":"1","description":"test","level":5,"groups":{groups_json}}},
            "decoder":{{"name":"{decoder}"}}
        }}"#
        );
        let (_, rec) = transform(&raw, "db", &[], &no_custom())
            .unwrap_or_else(|| panic!("transform failed for decoder={decoder}"));
        let violations = crate::pipeline::validator::validate_ocsf_record(&rec);
        assert!(
            violations.is_empty(),
            "decoder={decoder} groups={groups_json} → violations: {violations:?}"
        );
    }
}

#[test]
fn ocsf_type_uid_always_derived_correctly() {
    // Exhaustive check: type_uid == class_uid*100 + activity_id for every class path
    let test_cases: &[(&str, &str)] = &[
        (r#"["syscheck","syscheck_file"]"#, "syscheck"),
        (r#"["sshd","authentication_failed"]"#, "sshd"),
        (r#"["firewall","iptables"]"#, "iptables"),
        (r#"["ids","suricata"]"#, "suricata"),
        (r#"["vulnerability-detector"]"#, "vulnerability-detector"),
        (r#"["dns"]"#, "named"),
    ];
    for (groups_json, decoder) in test_cases {
        let raw = format!(
            r#"{{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{{"id":"1","name":"h","ip":""}},
            "rule":{{"id":"1","description":"t","level":3,"groups":{groups_json}}},
            "decoder":{{"name":"{decoder}"}}
        }}"#
        );
        let (_, rec) = transform(&raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(
            rec.type_uid,
            rec.class_uid * 100 + rec.activity_id as u32,
            "decoder={decoder}: type_uid mismatch"
        );
    }
}

// ── Bottleneck / performance invariants ──────────────────────────────

#[test]
fn transform_empty_line_returns_none() {
    assert!(transform("", "db", &[], &no_custom()).is_none());
    assert!(transform("   \t\n", "db", &[], &no_custom()).is_none());
}

#[test]
fn transform_handles_giant_data_object_without_panic() {
    // 1000-key data object — must not OOM or panic
    let mut data_obj = serde_json::Map::new();
    for i in 0..1000 {
        data_obj.insert(format!("field_{i}"), Value::String(format!("value_{i}")));
    }
    let alert = serde_json::json!({
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "1", "name": "stress-host", "ip": ""},
        "rule":  {"id": "1", "description": "stress", "level": 3},
        "data":  data_obj
    });
    let raw = serde_json::to_string(&alert).unwrap();
    let result = transform(&raw, "db", &[], &no_custom());
    assert!(
        result.is_some(),
        "large data object must transform without panic"
    );
    let (_, rec) = result.unwrap();
    // All unmapped data fields must be captured in event_data
    assert!(
        rec.event_data.contains("field_999"),
        "last key must be in event_data (lossless)"
    );
}

#[test]
fn transform_deeply_nested_json_no_stackoverflow() {
    // 50-level deep nesting — must not stack-overflow
    let mut v = serde_json::json!({"leaf": "value"});
    for _ in 0..50 {
        v = serde_json::json!({"nested": v});
    }
    let alert = serde_json::json!({
        "agent": {"id": "1", "name": "h", "ip": ""},
        "rule":  {"id": "1", "description": "deep", "level": 3},
        "data":  v
    });
    let raw = serde_json::to_string(&alert).unwrap();
    // Must complete without stack-overflow; result can be Some or None
    let _ = transform(&raw, "db", &[], &no_custom());
}

#[test]
fn sanitize_very_long_agent_name_truncated_to_200() {
    let long = "a".repeat(300);
    let tbl = crate::pipeline::transform::routing_table("db", &long, "", &[]);
    // table name part (after "db.ocsf_") must be ≤ 200 chars
    let tbl_part = tbl.strip_prefix("db.ocsf_").unwrap_or(&tbl);
    assert!(
        tbl_part.len() <= 200,
        "table segment must be ≤ 200 chars, was {}",
        tbl_part.len()
    );
}

// ── Wazuh vulnerability detector full round-trip ──────────────────────

#[test]
fn transform_vuln_detector_full() {
    let raw = r#"{
        "@timestamp":"2024-06-01T10:00:00Z",
        "agent":  {"id":"010","name":"vuln-host","ip":"10.0.10.1"},
        "rule":   {"id":"23001","description":"CVE detected","level":7,
                   "groups":["vulnerability-detector"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"vulnerability-detector"},
        "data":{
            "vulnerability":{
                "cve":       "CVE-2024-99999",
                "title":     "Remote Code Execution",
                "severity":  "Critical",
                "status":    "Active",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
                "package":{
                    "name":         "openssl",
                    "version":      "1.1.1",
                    "architecture": "amd64"
                },
                "cvss":{
                    "cvss3":{
                        "base_score": 9.8
                    }
                }
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 2002, "must be Vulnerability Finding");
    assert_eq!(rec.cve_id, "CVE-2024-99999");
    assert_eq!(rec.cvss_score, 9.8f32);
    assert_eq!(rec.severity_id, 5, "Critical → severity_id=5");
    assert_eq!(rec.severity, "Critical");
    assert_eq!(rec.app_name, "openssl", "package name → app_name");
    assert_eq!(rec.status, "Active");
    assert_eq!(rec.url, "https://nvd.nist.gov/vuln/detail/CVE-2024-99999");
    // OCSF validity
    let violations = crate::pipeline::validator::validate_ocsf_record(&rec);
    assert!(
        violations.is_empty(),
        "vuln record must pass OCSF validation: {violations:?}"
    );
}

// ── State persistence ─────────────────────────────────────────────────

#[test]
fn state_store_save_and_load_roundtrip() {
    let tmp = std::env::temp_dir().join("wazuh_ocsf_state_test.pos");
    let store = crate::input::state::StateStore::new(tmp.clone());
    let saved = crate::input::state::TailState {
        inode: 12345678,
        offset: 999999,
    };
    store.save(&saved).expect("save must succeed");
    let loaded = store.load();
    assert_eq!(loaded.inode, 12345678, "inode must round-trip");
    assert_eq!(loaded.offset, 999999, "offset must round-trip");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn state_store_missing_file_returns_defaults() {
    let tmp = std::env::temp_dir().join("wazuh_ocsf_state_nonexistent_xyz.pos");
    let _ = std::fs::remove_file(&tmp); // ensure it doesn't exist
    let store = crate::input::state::StateStore::new(tmp);
    let s = store.load();
    assert_eq!(s.inode, 0, "missing state file → inode=0");
    assert_eq!(s.offset, 0, "missing state file → offset=0");
}

#[test]
fn state_store_corrupt_file_returns_defaults() {
    let tmp = std::env::temp_dir().join("wazuh_ocsf_state_corrupt.pos");
    std::fs::write(&tmp, "not_valid_key_value_format\nbinary\x01data").unwrap();
    let store = crate::input::state::StateStore::new(tmp.clone());
    let s = store.load();
    // Corrupt data → should not panic, returns 0/0 or partial parse
    assert!(s.inode < u64::MAX, "must not panic on corrupt state");
    assert!(s.offset < u64::MAX, "must not panic on corrupt state");
    let _ = std::fs::remove_file(&tmp);
}

// ── activity_id gap fixes ─────────────────────────────────────────────

#[test]
fn transform_fim_renamed_maps_to_rename_activity() {
    // syscheck.event="renamed" must produce activity_id=5, not erroneously Create(1)
    let raw = r#"{
        "@timestamp":"2026-03-14T10:00:00Z",
        "agent":  {"id":"001","name":"host","ip":"10.0.0.1"},
        "rule":   {"id":"550","description":"FIM renamed","level":7,
                   "groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "syscheck":{"event":"renamed","path":"/etc/passwd","mode":"realtime"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 5, "renamed → Rename(5)");
    assert_eq!(rec.activity_name, "Rename", "activity_name must match");
    assert_eq!(rec.file_name, "/etc/passwd");
}

#[test]
fn transform_fim_moved_maps_to_rename_activity() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:01:00Z",
        "agent":  {"id":"001","name":"host","ip":"10.0.0.1"},
        "rule":   {"id":"550","description":"FIM moved","level":7,
                   "groups":["syscheck","syscheck_file"]},
        "decoder":{"name":"syscheck"},
        "syscheck":{"event":"moved","path":"/tmp/exploit","mode":"realtime"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 5, "moved → Rename(5)");
    assert_eq!(rec.activity_name, "Rename");
}

#[test]
fn transform_dns_response_group_maps_to_response_activity() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:02:00Z",
        "agent":  {"id":"001","name":"dns-srv","ip":"10.0.0.53"},
        "rule":   {"id":"23501","description":"DNS response","level":3,
                   "groups":["dns","dns_response","named"]},
        "decoder":{"name":"named"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4003, "DNS class");
    assert_eq!(rec.activity_id, 2, "dns_response group → Response(2)");
    assert_eq!(rec.activity_name, "Response");
}

#[test]
fn transform_dns_query_default_activity() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:03:00Z",
        "agent":  {"id":"001","name":"dns-srv","ip":"10.0.0.53"},
        "rule":   {"id":"23500","description":"DNS query","level":3,
                   "groups":["dns","named"]},
        "decoder":{"name":"named"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 1, "default DNS → Query(1)");
    assert_eq!(rec.activity_name, "Query");
}

#[test]
fn transform_dhcp_release_activity() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:04:00Z",
        "agent":  {"id":"001","name":"dhcp-srv","ip":"10.0.0.1"},
        "rule":   {"id":"5800","description":"DHCP release","level":3,
                   "groups":["dhcp"]},
        "decoder":{"name":"dhcpd"},
        "data":   {"action":"DHCPRELEASE"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.class_uid, 4004, "DHCP class");
    assert_eq!(rec.activity_id, 3, "DHCPRELEASE → Release(3)");
    assert_eq!(rec.activity_name, "Release");
}

#[test]
fn transform_dhcp_renew_activity() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:05:00Z",
        "agent":  {"id":"001","name":"dhcp-srv","ip":"10.0.0.1"},
        "rule":   {"id":"5801","description":"DHCP request","level":3,
                   "groups":["dhcp"]},
        "decoder":{"name":"dhcpd"},
        "data":   {"action":"DHCPREQUEST"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 2, "DHCPREQUEST → Renew(2)");
    assert_eq!(rec.activity_name, "Renew");
}

#[test]
fn transform_dhcp_error_activity() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:06:00Z",
        "agent":  {"id":"001","name":"dhcp-srv","ip":"10.0.0.1"},
        "rule":   {"id":"5802","description":"DHCP nak","level":5,
                   "groups":["dhcp"]},
        "decoder":{"name":"dhcpd"},
        "data":   {"action":"DHCPNAK"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 4, "DHCPNAK → Error(4)");
    assert_eq!(rec.activity_name, "Error");
}

#[test]
fn transform_dhcp_assign_default() {
    let raw = r#"{
        "@timestamp":"2026-03-14T10:07:00Z",
        "agent":  {"id":"001","name":"dhcp-srv","ip":"10.0.0.1"},
        "rule":   {"id":"5803","description":"DHCP ack","level":3,
                   "groups":["dhcp"]},
        "decoder":{"name":"dhcpd"},
        "data":   {"action":"DHCPACK"}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.activity_id, 1, "DHCPACK → Assign(1)");
    assert_eq!(rec.activity_name, "Assign");
}

// ── SCA (Security Configuration Assessment) field mapping ────────────

#[test]
fn transform_sca_maps_typed_columns() {
    let raw = r#"{
        "@timestamp":"2026-03-17T08:00:00Z",
        "agent":  {"id":"010","name":"win-desktop-01","ip":"10.0.1.10"},
        "rule":   {"id":"19009","description":"SCA check result","level":7,
                   "groups":["sca"]},
        "manager":{"name":"wazuh-mgr"},
        "decoder":{"name":"sca"},
        "data":{
            "sca":{
                "type":       "check",
                "scan_id":    "1234567890",
                "policy":     "CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0",
                "policy_id":  "cis_win10_enterprise",
                "check":{
                    "id":     "15542",
                    "title":  "Ensure Network access: Allow anonymous SID/Name translation is Disabled",
                    "result": "failed",
                    "compliance":{"cis":"2.3.10.1","cis_csc":"8.5"},
                    "description": "Prevents anonymous SID lookups.",
                    "rationale":   "Reduces attack surface.",
                    "remediation": "Set GPO to Disabled."
                }
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();

    // Typed OCSF columns
    assert_eq!(rec.class_uid, 2003, "SCA → Compliance Finding (2003)");
    assert_eq!(
        rec.finding_title,
        "Ensure Network access: Allow anonymous SID/Name translation is Disabled",
        "finding_title should come from sca.check.title, not rule description"
    );
    assert_eq!(
        rec.finding_uid, "19009",
        "finding_uid must always be the Wazuh rule_id — never overridden"
    );
    assert_eq!(rec.status, "failed", "status should be sca.check.result");
    assert_eq!(
        rec.app_name, "CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0",
        "app_name should be sca.policy"
    );

    // Extensions
    let ext: serde_json::Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(ext["sca_scan_id"], "1234567890");
    assert_eq!(
        ext["sca_check_id"], "15542",
        "sca.check.id goes to extensions, not finding_uid"
    );
    assert_eq!(ext["sca_cis_control"], "2.3.10.1");
    assert_eq!(ext["sca_cis_csc"], "8.5");
    assert!(ext["sca_description"]
        .as_str()
        .unwrap()
        .contains("anonymous"));
    assert!(ext["sca_rationale"]
        .as_str()
        .unwrap()
        .contains("attack surface"));
    assert!(ext["sca_remediation"].as_str().unwrap().contains("GPO"));
}

#[test]
fn transform_sca_pass_status() {
    let raw = r#"{
        "@timestamp":"2026-03-17T08:01:00Z",
        "agent":  {"id":"010","name":"win-desktop-01","ip":"10.0.1.10"},
        "rule":   {"id":"19101","description":"SCA check passed","level":3,
                   "groups":["sca"]},
        "decoder":{"name":"sca"},
        "data":{"sca":{"check":{"id":"15543","title":"Audit Policy Check","result":"passed"}}}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    assert_eq!(rec.status, "passed");
    assert_eq!(
        rec.finding_uid, "19101",
        "finding_uid must always be Wazuh rule_id"
    );
    let ext: serde_json::Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(
        ext["sca_check_id"], "15543",
        "sca.check.id must be in extensions"
    );
}

// ── Linux audit / SELinux AVC field mapping ──────────────────────────

#[test]
fn transform_audit_avc_maps_file_name_and_audit_type() {
    let raw = r#"{
        "@timestamp":"2026-03-17T08:02:00Z",
        "agent":  {"id":"005","name":"linux-srv","ip":"10.0.0.5"},
        "rule":   {"id":"80791","description":"SELinux AVC denial","level":8,
                   "groups":["audit"]},
        "decoder":{"name":"auditd"},
        "data":{
            "audit":{
                "id":   "46712",
                "type": "AVC",
                "directory":{"name":"snap.yq.yq"}
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();

    // file_name from audit.directory.name
    assert_eq!(
        rec.file_name, "snap.yq.yq",
        "file_name must come from audit.directory.name"
    );
    // finding_uid is always the Wazuh rule_id — audit.id goes to extensions
    assert_eq!(
        rec.finding_uid, "80791",
        "finding_uid must always be Wazuh rule_id"
    );
    // audit_type and audit_id in extensions
    let ext: serde_json::Value = serde_json::from_str(&rec.extensions).unwrap();
    assert_eq!(ext["audit_type"], "AVC");
    assert_eq!(ext["audit_id"], "46712", "audit.id must be in extensions");
}

// ── Windows SCM param1-7 and event binary in extensions ──────────────

#[test]
fn transform_win_eventdata_params_in_extensions() {
    let raw = r#"{
        "@timestamp":"2026-03-17T08:03:00Z",
        "agent":  {"id":"007","name":"win-srv-02","ip":"10.0.2.7"},
        "rule":   {"id":"7036","description":"Windows service state change","level":3,
                   "groups":["windows"]},
        "decoder":{"name":"windows_eventchannel"},
        "data":{
            "win":{
                "system":{"eventID":"7036","computer":"WIN-SRV-02"},
                "eventdata":{
                    "param1": "Windows Update",
                    "param2": "running",
                    "param3": "auto start",
                    "binary": "AABBCCDD"
                }
            }
        }
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    let ext: serde_json::Value = serde_json::from_str(&rec.extensions).unwrap();

    assert_eq!(
        ext["win_param1"], "Windows Update",
        "param1 must be in extensions"
    );
    assert_eq!(ext["win_param2"], "running", "param2 must be in extensions");
    assert_eq!(
        ext["win_param3"], "auto start",
        "param3 must be in extensions"
    );
    assert_eq!(
        ext["win_event_binary"], "AABBCCDD",
        "binary must be win_event_binary"
    );
    assert_eq!(ext["win_event_id"], "7036", "event ID still present");
}

#[test]
fn transform_win_params_not_present_if_empty() {
    let raw = r#"{
        "@timestamp":"2026-03-17T08:04:00Z",
        "agent":  {"id":"007","name":"win-srv-02","ip":"10.0.2.7"},
        "rule":   {"id":"4625","description":"Windows logon failure","level":5,
                   "groups":["windows","authentication_failed"]},
        "decoder":{"name":"windows_eventchannel"},
        "data":{"win":{"system":{"eventID":"4625"},"eventdata":{"ipAddress":"1.2.3.4"}}}
    }"#;
    let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
    let ext: serde_json::Value = serde_json::from_str(&rec.extensions).unwrap();
    assert!(
        ext.get("win_param1").is_none(),
        "win_param1 must not appear when absent"
    );
    assert!(
        ext.get("win_event_binary").is_none(),
        "win_event_binary must not appear when absent"
    );
}
