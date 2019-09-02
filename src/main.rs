#![deny(//missing_docs,
        missing_debug_implementations, missing_copy_implementations,
        trivial_casts, trivial_numeric_casts,
        unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

/* === CRATES === */
extern crate failure;

extern crate clap;
extern crate csv;
extern crate regex;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate trust_dns;

/* === MODs === */

pub mod errors;

/* === USE === */

use std::result;
// use failure::ResultExt;
use clap::{App, Arg};
use errors::Error;
use regex::Regex;
use rusoto_core::Region;
use rusoto_ec2::{
    AuthorizeSecurityGroupIngressRequest, DescribeSecurityGroupsRequest, Ec2, Ec2Client,
    IpPermission, RevokeSecurityGroupIngressRequest, SecurityGroup,
};
use std::collections::HashMap;
use std::env::current_exe;
// use std::fmt;
use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientConnection;

/* === TYPES === */
type Result<T> = result::Result<T, failure::Error>;
type CsvRecord = (String, String, i64);

/* === CONSTANTS === */
const OPEN_DNS_ADDRESS: &str = "208.67.222.222:53";
const FILE_NAME: &str = "config/ports.csv";

/* === STRUCTS === */
/// Struct containing port number and protocol
#[derive(Hash, Eq, PartialEq, Debug)]
struct Port {
    protocol: String,
    port: i64,
}
/* === IMPLEMENTS === */
impl Port {
    fn new(protocol: String, port: i64) -> Port {
        Port { protocol, port }
    }
}

/* === FUNCTIONS ===*/
fn print_error(err: &failure::Error) -> String {
    let mut pretty = err.to_string();
    let mut prev = err.as_fail();
    while let Some(next) = prev.cause() {
        pretty.push_str(": ");
        pretty.push_str(&next.to_string());
        prev = next;
    }
    pretty
}

/// Get service to port + protocol mapping from config file
fn get_rules() -> Result<(HashMap<String, Vec<Port>>)> {
    let mut file_path = current_exe()?;
    file_path.pop();
    file_path.push(FILE_NAME);

    let mut rdr = csv::Reader::from_path(file_path).map_err(|err| Error::config(err.to_string()))?;
    let mut rules: HashMap<String, Vec<Port>> = HashMap::new();

    for record in rdr.deserialize() {
        let (name, protocol, port): CsvRecord = record?;
        let entry_vector = rules.entry(name).or_insert_with(Vec::new);
        entry_vector.push(Port::new(protocol, port));
    }
    Ok(rules)
}

/// Make DNS request to opendns for current external ip
fn get_external_ip() -> Result<String> {
    let name = Name::from_str("myip.opendns.com.").unwrap();
    let client = SyncClient::new(UdpClientConnection::new(OPEN_DNS_ADDRESS.parse()?).unwrap());
    let response = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

    if let RData::A(ref ip) = *response.answers()[0].rdata() {
        let mut final_str = "".to_owned();
        let mut octet_number = 1;
        for i in &ip.octets() {
            final_str.push_str(&i.to_string());
            if octet_number != 4 {
                final_str.push_str(".");
            }
            octet_number += 1;
        }
        return Ok(final_str);
    }
    Err(Error::obtain_ip())?
}

/// Prints a ip_permission rule
fn print_ip_rule(rule: IpPermission) {
    let ip_protocol = rule.ip_protocol.unwrap();
    if ip_protocol == "-1" {
        print!("tcp/udp *");
    } else {
        print!("{} ", ip_protocol);

        if let Some(from_port) = rule.from_port {
            print!("{}", from_port)
        };
        print!("->");
        if let Some(to_port) = rule.to_port {
            print!("{}", to_port)
        };
    }
    println!();

    if let Some(ranges) = rule.ip_ranges {
        for cidr_ip in ranges
            .into_iter()
            .filter(|range| range.cidr_ip.is_some())
            .map(|range| range.cidr_ip.unwrap())
            .collect::<Vec<String>>()
        {
            println!("\t{}", cidr_ip);
        }
    }
    if let Some(groups_pairs) = rule.user_id_group_pairs {
        for group in groups_pairs {
            if let Some(ref id) = group.group_id {
                if let Some(ref name) = group.group_name {
                    println!("\t{} {}", id, name)
                } else {
                    println!("\t{}", id)
                }
            }
        }
    };
    println!();
}

/// Prints a security-group for a list view format
fn print_security_group_list(sg: SecurityGroup) {
    if let Some(id) = sg.group_id {
        print!("{}", id)
    };
    if let Some(name) = sg.group_name {
        print!("\t{}", name)
    };
    println!();
}

/// Prints a security-group for a detailed view format
fn print_security_group_detail(sg: SecurityGroup) {
    if let Some(id) = sg.group_id {
        print!("{}", id)
    };
    if let Some(name) = sg.group_name {
        println!("\t{}", name)
    };
    if let Some(description) = sg.description {
        println!("{}", description)
    };
    println!();

    println!("Ingress Rules");
    println!("--------------------");
    if let Some(ip_permissions) = sg.ip_permissions {
        for ip_permission in ip_permissions {
            print_ip_rule(ip_permission);
        }
    }

    println!("Egress Rules");
    println!("--------------------");
    if let Some(ip_permissions) = sg.ip_permissions_egress {
        for ip_permission in ip_permissions {
            print_ip_rule(ip_permission);
        }
    }
}

/// Main function for error handling
fn main() {
    if let Err(e) = run() {
        use std::io::Write;
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", print_error(&e)).unwrap_or_else(|_| panic!(errmsg));

        let backtrace = e.backtrace().to_string();
        if !backtrace.trim().is_empty() {
            writeln!(stderr, "backtrace: {}", backtrace).unwrap_or_else(|_| panic!(errmsg));
        }

        ::std::process::exit(1);
    }
}

/// Bulk of the execution
fn run() -> Result<()> {
    let valid_total_ip_reg = Regex::new(r"^[0-9]+.[0-9]+.[0-9]+.[0-9]+/[0-9]{1,2}$").unwrap();
    let valid_ip_reg = Regex::new(r"^[0-9]+.[0-9]+.[0-9]+.[0-9]+$").unwrap();

    // Init command line arguments
    let matches = App::new("aws-sg-util")
        .version("1.0")
        .about("Simple utility to help list, add, and remove permissions quickly from AWS security groups")
        .author("Jonathan Constantinides <jonleecon@gmail.com>")
        .arg(
            Arg::with_name("list")
                .short("l")
                .long("list")
                .help("List information")
        )
        .arg(
            Arg::with_name("security-group")
                .long("sg")
                .value_name("SECURITY_GROUP")
                .help("Set specific security group")
        )
        .arg(
            Arg::with_name("ip")
                .long("ip")
                .value_name("IP_ADDRESS")
                .help("Set specific ip address")
        )
        .arg(
            Arg::with_name("add")
                .short("a")
                .long("add")
                .value_name("DEFINED_SERVICE")
                .help("Add service/port (number)")
        )
        .arg(
            Arg::with_name("remove")
                .short("r")
                .long("remove")
                .value_name("DEFINED_SERVICE")
                .help("Remove service/port (number)")
        )
        .get_matches();

    // Init EC2 client for AWS requests
    let client = Ec2Client::new(Region::UsWest2);

    // Closure to print security groups
    let print_securitygroups = || {
        let output = client
            .describe_security_groups(Default::default())
            .sync()
            .unwrap();

        if let Some(security_groups) = output.security_groups {
            println!("Name\t\tId");
            println!("-----------------------------------------");

            for security_group in security_groups {
                print_security_group_list(security_group);
            }
        }
    };

    if matches.is_present("list") {
        if let Some(sg) = matches.value_of("security-group") {
            let describe_security_group_request = DescribeSecurityGroupsRequest {
                group_ids: Some(vec![sg.to_string()]),
                ..Default::default()
            };

            let security_groups = client
                .describe_security_groups(describe_security_group_request)
                .sync()?
                .security_groups
                .unwrap();

            for security_group in security_groups {
                print_security_group_detail(security_group);
            }
        } else {
            print_securitygroups();
        }
    } else if matches.is_present("add") && matches.is_present("remove") {
        Err(Error::incorrect_args("add and remove both provided"))?
    } else if matches.is_present("add") || matches.is_present("remove") {
        let add_option = matches.is_present("add");
        if !matches.is_present("security-group") {
            Err(Error::missing_arg("security-group"))?
        }
        let security_group = matches.value_of("security-group").unwrap();
        let service = if add_option {
            matches.value_of("add").unwrap()
        } else {
            matches.value_of("remove").unwrap()
        };

        let services: HashMap<String, Vec<Port>>;
        let set_port;
        let ports; //: Vec<Port>;

        if let Ok(user_defined_port) = service.parse::<i64>() {
            set_port = vec![Port::new("tcp".to_string(), user_defined_port)];
            ports = &set_port;
        } else {
            services = get_rules()?;
            ports = services
                .get(service)
                .expect("Service not specificed in configuration file");
        }

        // Finalize IP
        let mut use_ip = if matches.is_present("ip") {
            matches.value_of("ip").unwrap().to_owned()
        } else {
            get_external_ip()?
        };

        // Add prefix if needed
        if valid_ip_reg.is_match(&use_ip) {
            use_ip.push_str("/32");
        }
        if !valid_total_ip_reg.is_match(&use_ip) {
            Err(Error::invalid_ip())?
        }

        for port in ports.iter() {
            let set_protocol = port.protocol.clone();
            let set_port = port.port;
            if add_option {
                client
                    .authorize_security_group_ingress(AuthorizeSecurityGroupIngressRequest {
                        cidr_ip: Some(use_ip.to_owned()),
                        group_id: Some(security_group.to_string()),
                        from_port: Some(set_port),
                        to_port: Some(set_port),
                        ip_protocol: Some(set_protocol),
                        ..Default::default()
                    })
                    .sync()?;
            } else {
                client
                    .revoke_security_group_ingress(RevokeSecurityGroupIngressRequest {
                        cidr_ip: Some(use_ip.to_owned()),
                        group_id: Some(security_group.to_string()),
                        from_port: Some(set_port),
                        to_port: Some(set_port),
                        ip_protocol: Some(set_protocol),
                        ..Default::default()
                    })
                    .sync()?;
            }
        }
        println!(
            "{} service:{:?} to security-group:{:?} successfully",
            if add_option { "Added" } else { "Removed" },
            service,
            security_group
        );
    }

    Ok(())
}
