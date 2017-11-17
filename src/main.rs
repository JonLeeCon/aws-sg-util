#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate trust_dns;
extern crate csv;
extern crate clap;

/* MODULES */
mod errors {
    error_chain!{}
}

/* USE */
use std::collections::HashMap;
// use std::fmt;
// use std::net::Ipv4Addr;
use std::str::FromStr;

use errors::*;

use rusoto_core::{DefaultCredentialsProvider, Region, default_tls_client};
use rusoto_ec2::{Ec2Client, Ec2, DescribeSecurityGroupsRequest, AuthorizeSecurityGroupIngressRequest, RevokeSecurityGroupIngressRequest, SecurityGroup};
// use rusoto_ec2::{UserIdGroupPair};
use trust_dns::client::{Client, SyncClient};
use trust_dns::udp::UdpClientConnection;
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use clap::{App, Arg /*, SubCommand */};

/* CONSTANTS */
const OPEN_DNS_ADDRESS: &'static str = "208.67.222.222:53";
const FILE_NAME: &'static str = "./config/ports.csv";

/* STRUCTS */
#[derive(Hash, Eq, PartialEq, Debug)]
struct Port {
    protocol: String,
    port: i64,
}

impl Port {
    fn new(protocol: String, port: i64) -> Port {
        Port {
            protocol: protocol,
            port: port,
        }
    }
}

// impl Into<PUserIdGroupPair> for UserIdGroupPair {
//   fn into(self) -> PUserIdGroupPair {
//     PUserIdGroupPair(self)
//   }
// }

/*
struct PVec<T>(Vec<T>);
struct PUserIdGroupPair(UserIdGroupPair);

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

impl<T> fmt::Display for PVec<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut print_separated = String::new();

        for num in &self.0[0..self.0.len() - 1] {
            print_separated.push_str(&num.to_string());
            print_separated.push_str("\n");
        }
        print_separated.push_str(&self.0[self.0.len() - 1].to_string());
        write!(f, "{}", print_separated)
    }
}
*/

/* FUNCTIONS */
/*
fn print_definitions(rules: &HashMap<String, Vec<Port>>) {
    for (name, port) in rules {
        println!("{}: {:?}", name, port);
    }
}
*/

fn print_security_group(sg: SecurityGroup) {
    if let Some(id) = sg.group_id {
        println!("Id: {}", id)
    };
    if let Some(name) = sg.group_name {
        println!("Name: {}", name)
    };
    if let Some(description) = sg.description {
        println!("Description: {}", description)
    };
    println!("");
    /*
    let print_ip = |ip_input: Option<Vec<IpPermission>>| if let Some(ip_permissions) = ip_input {
        println!("Ingress Rules:");
        for rule in ip_permissions {
            if let Some(ip_protocol) = rule.ip_protocol {
                print!("{} ", ip_protocol)
            };
            if let Some(from_port) = rule.from_port {
                print!("{}", from_port)
            };
            print!("->");
            if let Some(to_port) = rule.to_port {
                print!("{}", to_port)
            };
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
    print_ip(sg.ip_permissions);
    print_ip(sg.ip_permissions_egress);
    */
}

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

fn run() -> Result<()> {
    // Init
    let matches = App::new("aws-sg-util")
        .version("1.0")
        .about(
            "Simple utility to help add and remove permissions quickly from AWS security groups",
        )
        .author("Jonathan Constantinides <jonleecon@gmail.com>")
        .arg(Arg::with_name("list").short("l").long("list").help(
            "List information",
        ))
        .arg(
            Arg::with_name("security-group")
                .long("sg")
                .value_name("SECURITY_GROUP")
                .help("Set specific security group"),
        )
        .arg(
            Arg::with_name("add")
                .short("a")
                .long("add")
                .value_name("DEFINED_SERVICE")
                .help("Add service"),
        )
        .arg(
            Arg::with_name("remove")
                .short("r")
                .long("remove")
                .value_name("DEFINED_SERVICE")
                .help("Remove service"),
        )
        .get_matches();

    let get_rules = || {
        let mut rules = HashMap::new();
        // let mut rules: HashMap<String, Vec<Port>> = HashMap::new();
        let mut rdr = csv::Reader::from_file(FILE_NAME).unwrap();
        for record in rdr.decode() {
            let (name, protocol, port): (String, String, i64) = record.unwrap();
            let entry_vector = rules.entry(name).or_insert(Vec::new());
            entry_vector.push(Port::new(protocol, port));
        }
        rules
    };

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
            Some(final_str)
        }
        else { None }
    };
    // print_definitions(&rules);

    let client = Ec2Client::new(
        default_tls_client().unwrap(),
        DefaultCredentialsProvider::new().unwrap(),
        Region::UsWest2,
    );

    let print_securitygroups = || {
        let describe_security_group_request: DescribeSecurityGroupsRequest = Default::default();
        let output = client
            .describe_security_groups(&describe_security_group_request)
            .unwrap();
        if let Some(security_groups) = output.security_groups {
            println!("Security Groups:");

            for security_group in security_groups {
                print_security_group(security_group);
                /*
          match security_group {
            SecurityGroup { 
              ref group_name,
              group_id: Some(ref id),
              ..
            } => {
              if let Some(ref name) = *group_name {
                println!("{} {}", id, name);
              }
              else {
                println!("{}", id);
              }
            }
            _ => {}
          }
          */
            }
        }
    };

    // List Action
    if matches.is_present("list") {
        if let Some(sg) = matches.value_of("security-group") {
            let describe_security_group_request = DescribeSecurityGroupsRequest {
                group_ids: Some(vec![sg.to_string()]),
                ..Default::default()
            };

            let security_groups = client
                .describe_security_groups(&describe_security_group_request)
                .unwrap()
                .security_groups
                .unwrap();

            for security_group in security_groups {
                print_security_group(security_group);
            }
        } else {
            print_securitygroups();
        }
    }
    // Add action
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

        let sg = matches.value_of("security-group").unwrap();
        let service = matches.value_of("add").unwrap().to_string();
        let services: HashMap<String, Vec<Port>> = get_rules();

        let ports = services.get(&service).unwrap();
        let my_ip = get_external_ip().unwrap();

        for port in ports.into_iter() {
          let set_protocol = port.protocol.clone();
          let set_port = port.port;
          client
            .authorize_security_group_ingress(
              &AuthorizeSecurityGroupIngressRequest {
                cidr_ip: Some(my_ip.clone() + "/32"),
                group_id: Some(sg.to_string()),
                from_port: Some(set_port),
                to_port: Some(set_port),
                ip_protocol: Some(set_protocol),
                ..Default::default()
              }
            )
            .unwrap();
        }
        println!("Added service:{:?} to security-group:{:?} successfully", service, sg);
    }
    // Remove action
    else if matches.is_present("remove") {
        // Missing add argument
        if !matches.is_present("remove") {
            bail!("Missing required pre-defined service to remove");
        }
        // Missing sg
        if !matches.is_present("security-group") {
            bail!("Missing required security-group when removing rule");
        }

        let sg = matches.value_of("security-group").unwrap();
        let service = matches.value_of("remove").unwrap().to_string();
        let services: HashMap<String, Vec<Port>> = get_rules();

        let ports = services.get(&service).unwrap();
        let my_ip = get_external_ip().unwrap();

        for port in ports.into_iter() {
          let set_protocol = port.protocol.clone();
          let set_port = port.port;
          client
            .revoke_security_group_ingress(
              &RevokeSecurityGroupIngressRequest {
                cidr_ip: Some(my_ip.clone() + "/32"),
                group_id: Some(sg.to_string()),
                from_port: Some(set_port),
                to_port: Some(set_port),
                ip_protocol: Some(set_protocol),
                ..Default::default()
              }
            )
            .unwrap();
        }
        println!("Removed service:{:?} to security-group:{:?} successfully", service, sg);
    }

    Ok(())
}
