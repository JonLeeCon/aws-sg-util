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
extern crate regex;

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
use regex::Regex;

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

/// Get service to port + protocol mapping from config file
fn get_rules() -> Result<(HashMap<String, Vec<Port>>)> {
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
}

/// Make DNS request to opendns for current external ip
fn get_external_ip () -> Result<String> {
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
        return Ok(final_str);
    }
    bail!("Unable to get external ip from dns request")
}

/// Prints a ip_permission rule
fn print_ip_rule(rule: IpPermission) {
    let ip_protocol = rule.ip_protocol.unwrap();
    if ip_protocol == "-1" {
        print!("tcp/udp *");
    } else {
        print!("{} ", ip_protocol);

        if let Some(from_port) = rule.from_port { print!("{}", from_port) };
        print!("->");
        if let Some(to_port) = rule.to_port { print!("{}", to_port) };
    }
    println!();

    if let Some(ranges) = rule.ip_ranges {
        for cidr_ip in ranges.into_iter()
            .filter(|range| range.cidr_ip.is_some())
            .map(|range| range.cidr_ip.unwrap())
            .collect::<Vec<String>>()
        {
            println!("\t{}", cidr_ip);
        }
    }
    if let Some(groups_pairs) = rule.user_id_group_pairs {
        for group in groups_pairs {
            println!("\t{}", PUserIdGroupPair(group));
        }
    };
    println!();
}

/// Prints a security-group for a list view format
fn print_security_group_list(sg: SecurityGroup) {
    if let Some(id) = sg.group_id { print!("{}", id) };
    if let Some(name) = sg.group_name { print!("\t{}", name) };
    println!("");
}

/// Prints a security-group for a detailed view format
fn print_security_group_detail(sg: SecurityGroup) {
    if let Some(id) = sg.group_id { print!("{}", id) };
    if let Some(name) = sg.group_name { println!("\t{}", name) };
    if let Some(description) = sg.description { println!("{}", description) };
    println!("");

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

        let all_services: HashMap<String, Vec<Port>>;
        let ports: Vec<Port>;
        let add_ports: &Vec<Port>;

        if let Ok(user_defined_port) = add_service.parse::<i64>() {
            ports = vec![Port::new("tcp".to_string(), user_defined_port)];
            add_ports = &ports;
        }
        else {
            all_services = get_rules()?;
            add_ports = all_services.get(&add_service).expect("Service not specificed in configuration file");
        }

        // Finalize IP
        let mut use_ip;
        if matches.is_present("ip") {
            use_ip = matches.value_of("ip").unwrap().to_owned();
        }
        else {
            use_ip = get_external_ip()?;
        }

        // Add prefix if needed
        if valid_ip_reg.is_match(&use_ip) {
            use_ip.push_str("/32");
        }
        if !valid_total_ip_reg.is_match(&use_ip) {
            bail!("Invalid IP address")
        }

        for port in add_ports.into_iter() {
            let set_protocol = port.protocol.clone();
            let set_port = port.port;
            client
                .authorize_security_group_ingress(&AuthorizeSecurityGroupIngressRequest {
                    cidr_ip: Some(use_ip.to_owned()),
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

        let all_services: HashMap<String, Vec<Port>>;
        let ports: Vec<Port>;
        let remove_ports: &Vec<Port>;

        if let Ok(user_defined_port) = remove_service.parse::<i64>() {
            ports = vec![Port::new("tcp".to_string(), user_defined_port)];
            remove_ports = &ports;
        }
        else {
            all_services = get_rules()?;
            remove_ports = all_services.get(&remove_service).expect("Service not specificed in configuration file");
        }
        
        let mut use_ip;
        if matches.is_present("ip") {
            use_ip = matches.value_of("ip").unwrap().to_owned();
        }
        else {
            use_ip = get_external_ip()?;
        }

        // Add prefix if needed
        if valid_ip_reg.is_match(&use_ip) {
            use_ip.push_str("/32");
        }
        if !valid_total_ip_reg.is_match(&use_ip) {
            bail!("Invalid IP address")
        }

        for port in remove_ports.into_iter() {
            let set_protocol = port.protocol.clone();
            let set_port = port.port;
            client
                .revoke_security_group_ingress(&RevokeSecurityGroupIngressRequest {
                    cidr_ip: Some(use_ip.to_owned()),
                    // cidr_ip: Some(String::from(test_ip)),
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
