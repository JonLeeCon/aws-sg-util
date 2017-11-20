#![recursion_limit = "1024"]

/* === CRATES === */

#[macro_use]
extern crate error_chain;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate trust_dns;
extern crate csv;
extern crate clap;
extern crate process_path;

/* === MODs === */

mod errors {
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
            TlsError(::rusoto_core::TlsError);
            CredentialError(::rusoto_core::CredentialsError);
            CSVError(::csv::Error);
            AuthorizeSecurityGroupIngressError(::rusoto_ec2::AuthorizeSecurityGroupIngressError);
            RevokeSecurityGroupIngressError(::rusoto_ec2::RevokeSecurityGroupIngressError);
            DescribeSecurityGroupsError(::rusoto_ec2::DescribeSecurityGroupsError);
        }
    }
}

/* === USE === */

use process_path::get_executable_path;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use errors::*;
use rusoto_core::{DefaultCredentialsProvider, Region, default_tls_client};
use rusoto_ec2::{Ec2Client, Ec2, DescribeSecurityGroupsRequest,
                 AuthorizeSecurityGroupIngressRequest, RevokeSecurityGroupIngressRequest,
                 SecurityGroup, UserIdGroupPair, IpPermission};
use trust_dns::client::{Client, SyncClient};
use trust_dns::udp::UdpClientConnection;
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use clap::{App, Arg};

/* === CONSTANTS === */

const OPEN_DNS_ADDRESS: &'static str = "208.67.222.222:53";
const FILE_NAME: &'static str = "config/ports.csv";

/* === STRUCTS === */

/// Struct containing port number and protocol
#[derive(Hash, Eq, PartialEq, Debug)]
struct Port {
    protocol: String,
    port: i64,
}

/// Wrapper struct for printing
struct PUserIdGroupPair(UserIdGroupPair);

/* === IMPLEMENTS === */

impl Port {
    fn new(protocol: String, port: i64) -> Port {
        Port {
            protocol: protocol,
            port: port,
        }
    }
}

impl Into<PUserIdGroupPair> for UserIdGroupPair {
    fn into(self) -> PUserIdGroupPair {
        PUserIdGroupPair(self)
    }
}

impl fmt::Display for PUserIdGroupPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref id) = self.0.group_id {
            if let Some(ref name) = self.0.group_name {
                write!(f, "{} {}", id, name)
            } else {
                write!(f, "{}", id)
            }
        } else {
            write!(f, "")
        }
    }
}

/* === FUNCTIONS ===*/

/// Prints a security-group for a list view format
fn print_security_group_list(sg: SecurityGroup) {
    if let Some(id) = sg.group_id {
        print!("{}\t", id)
    };
    if let Some(name) = sg.group_name {
        print!("{}\t", name)
    };
    println!("");
}

/// Prints a security-group for a detailed view format
fn print_security_group_detail(sg: SecurityGroup) {
    if let Some(id) = sg.group_id {
        print!("{}", id)
    };
    if let Some(name) = sg.group_name {
        println!("-{}", name)
    };
    if let Some(description) = sg.description {
        println!("{}", description)
    };
    println!("");
    let print_ip = |ip_input: Option<Vec<IpPermission>>| if let Some(ip_permissions) = ip_input {
        for rule in ip_permissions {
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
            if let Some(ip_ranges) = rule.ip_ranges {
                for range in ip_ranges {
                    if let Some(cidr_ip) = range.cidr_ip {
                        println!("\t{}", cidr_ip)
                    };
                }
            }
            if let Some(groups_pairs) = rule.user_id_group_pairs {
                for group in groups_pairs {
                    println!("\t{}", PUserIdGroupPair(group));
                }
            };
            println!();
        }
    };

    println!("Ingress Rules");
    println!("--------------------");
    print_ip(sg.ip_permissions);

    println!("Egress Rules");
    println!("--------------------");
    print_ip(sg.ip_permissions_egress);
}

/// Main function for error handling
fn main() {
    if let Err(ref e) = run() {
        use std::io::Write;
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        for e in e.iter().skip(1) {
            writeln!(stderr, "caused by: {}", e).expect(errmsg);
        }

        if let Some(backtrace) = e.backtrace() {
            writeln!(stderr, "backtrace: {:?}", backtrace).expect(errmsg);
        }

        ::std::process::exit(1);
    }
}

/// Bulk of the execution
fn run() -> Result<()> {
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
            Arg::with_name("add")
                .short("a")
                .long("add")
                .value_name("DEFINED_SERVICE")
                .help("Add service")
        )
        .arg(
            Arg::with_name("remove")
                .short("r")
                .long("remove")
                .value_name("DEFINED_SERVICE")
                .help("Remove service")
        )
        .get_matches();

    // Init EC2 client for AWS requests
    let client = Ec2Client::new(
        default_tls_client()?,
        DefaultCredentialsProvider::new()?,
        Region::UsWest2,
    );

    // Get service to port + protocol mapping from config file
    let get_rules = || -> Result<(HashMap<String, Vec<Port>>)> {
        let mut get_exec_path = get_executable_path().unwrap();
        get_exec_path.pop();
        get_exec_path.push(FILE_NAME);

        let mut rules: HashMap<String, Vec<Port>> = HashMap::new();
        let mut rdr = csv::Reader::from_file(get_exec_path)?;
        for record in rdr.decode() {
            let (name, protocol, port): (String, String, i64) = record?;
            let entry_vector = rules.entry(name).or_insert(Vec::new());
            entry_vector.push(Port::new(protocol, port));
        }
        Ok(rules)
    };

    // Make DNS request to opendns for current external ip
    let get_external_ip = || {
        let name = Name::from_str("myip.opendns.com.").unwrap();
        let client = SyncClient::new(
            UdpClientConnection::new(OPEN_DNS_ADDRESS.parse().unwrap()).unwrap(),
        );
        let response: Message = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

        if let &RData::A(ref ip) = response.answers()[0].rdata() {
            let mut final_str = "".to_owned();
            let mut octet_number = 1;
            for i in &ip.octets() {
                final_str.push_str(&i.to_string());
                if octet_number != 4 {
                    final_str.push_str(".");
                }
                octet_number = octet_number + 1;
            }
            Ok(final_str)
        } else {
            Err("Unable to get external ip from dns request")
        }
    };

    // Closure to print security groups
    let print_securitygroups = || {
        let output = 
        client.describe_security_groups(&Default::default()).unwrap();
        
        if let Some(security_groups) = output.security_groups {
            println!("Name\t\tId");
            println!("-----------------------------------------");

            for security_group in security_groups {
                print_security_group_list(security_group);
            }
        }
    };

    // List
    if matches.is_present("list") {
        if let Some(sg) = matches.value_of("security-group") {
            let describe_security_group_request = DescribeSecurityGroupsRequest {
                group_ids: Some(vec![sg.to_string()]),
                ..Default::default()
            };

            let security_groups = client
                .describe_security_groups(&describe_security_group_request)?
                .security_groups.unwrap();

            for security_group in security_groups {
                print_security_group_detail(security_group);
            }
        } else {
            print_securitygroups();
        }
    }

    // Add
    else if matches.is_present("add") {
        // Missing add argument
        if !matches.is_present("add") {
            bail!("Missing required pre-defined service to add");
        }
        // Missing sg
        if !matches.is_present("security-group") {
            bail!("Missing required security-group when adding rule");
        }
        // Remove with add
        if matches.is_present("remove") {
            bail!("Cannot add and remove together");
        }

        let add_security_group = matches.value_of("security-group").unwrap();
        let add_service = matches.value_of("add").unwrap().to_string();
        let all_services: HashMap<String, Vec<Port>> = match get_rules() {
            Ok(res) => res,
            Err(err) => bail!("Error obtaining services from csv file: {}", err)
        };

        let add_ports = match all_services.get(&add_service) {
            Some(add_ports) => add_ports,
            _ => bail!("Service ports defitions were not found")
        };
        let external_ip = get_external_ip()?;

        for port in add_ports.into_iter() {
            let set_protocol = port.protocol.clone();
            let set_port = port.port;
            client
                .authorize_security_group_ingress(&AuthorizeSecurityGroupIngressRequest {
                    cidr_ip: Some(external_ip.clone() + "/32"),
                    group_id: Some(add_security_group.to_string()),
                    from_port: Some(set_port),
                    to_port: Some(set_port),
                    ip_protocol: Some(set_protocol),
                    ..Default::default()
                })
                .chain_err(|| { "Could not add port" })?;
        }
        println!(
            "Added service:{:?} to security-group:{:?} successfully",
            add_service,
            add_security_group
        );
    }

    // Remove
    else if matches.is_present("remove") {
        // Missing add argument
        if !matches.is_present("remove") {
            bail!("Missing required pre-defined service to remove");
        }
        // Missing sg
        if !matches.is_present("security-group") {
            bail!("Missing required security-group when removing rule");
        }

        let remove_security_group = matches.value_of("security-group").unwrap();
        let remove_service = matches.value_of("remove").unwrap().to_string();
        let all_services: HashMap<String, Vec<Port>> = match get_rules() {
            Ok(res) => res,
            Err(err) => bail!("Error obtaining services from csv file: {}", err)
        };

        let remove_ports = match all_services.get(&remove_service) {
            Some(remove_ports) => remove_ports,
            _ => bail!("Service ports defitions were not found")
        };
        let external_ip = get_external_ip()?;

        for port in remove_ports.into_iter() {
            let set_protocol = port.protocol.clone();
            let set_port = port.port;
            client
                .revoke_security_group_ingress(&RevokeSecurityGroupIngressRequest {
                    cidr_ip: Some(external_ip.clone() + "/32"),
                    group_id: Some(remove_security_group.to_string()),
                    from_port: Some(set_port),
                    to_port: Some(set_port),
                    ip_protocol: Some(set_protocol),
                    ..Default::default()
                })
                .chain_err(|| { "Could not remove port" })?;;
        }
        println!(
            "Removed service:{:?} to security-group:{:?} successfully",
            remove_service,
            remove_security_group
        );
    }

    Ok(())
}
