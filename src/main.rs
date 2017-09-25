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
use std::fmt;
// use std::net::Ipv4Addr;
use std::str::{FromStr};

use errors::*;

use rusoto_core::{DefaultCredentialsProvider, Region, default_tls_client};
use rusoto_ec2::{UserIdGroupPair, Ec2Client, Ec2, DescribeSecurityGroupsRequest, SecurityGroup, IpRange, IpPermission};
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
    port: usize,
}

impl Port {
  fn new(protocol: String, port: usize) -> Port {
    Port { protocol: protocol, port: port }
  }
}

// impl Into<PUserIdGroupPair> for UserIdGroupPair {
//   fn into(self) -> PUserIdGroupPair {
//     PUserIdGroupPair(self)
//   }
// }

struct PVec<T>(Vec<T>);
struct PUserIdGroupPair(UserIdGroupPair);

impl fmt::Display for PUserIdGroupPair {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    if let Some(ref id) = self.0.group_id {
      if let Some(ref name) = self.0.group_name {
        write!(f, "{} {}", id, name)
      }
      else {
        write!(f, "{}", id)
      }
    }
    else {
      write!(f, "")
    }
  }
}

impl<T> fmt::Display for PVec<T>
  where T: fmt::Display
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

/* FUNCTIONS */
fn print_definitions(rules: &HashMap<String, Vec<Port>>) {
  for (name, port) in rules {
        println!("{}: {:?}", name, port);
    }
}

fn print_security_group(sg: SecurityGroup) {
  if let Some(id) = sg.group_id { println!("Id: {}", id) };
  if let Some(name) = sg.group_name { println!("Name: {}", name) };
  if let Some(description) = sg.description { println!("Name: {}", description) };

  let print_ip = |ip_input: Option<Vec<IpPermission>>| {
    if let Some(ip_permissions) = ip_input {
      println!("Ingress Rules:");
      for rule in ip_permissions {
        if let Some(ip_protocol) = rule.ip_protocol { print!("{} ", ip_protocol) };
        if let Some(from_port) = rule.from_port { print!("{}", from_port) };
        print!("->");
        if let Some(to_port) = rule.to_port { print!("{}", to_port) };
        println!();
        if let Some(ip_ranges) = rule.ip_ranges {
          for range in ip_ranges {
            if let Some(cidr_ip) = range.cidr_ip { println!("\t{}", cidr_ip) };
          }
        }
        if let Some(groups_pairs) = rule.user_id_group_pairs {
          for group in groups_pairs {
            println!("\t{}", PUserIdGroupPair(group));
          }
        };
        println!();
      }
    }
  };
  print_ip(sg.ip_permissions);
  print_ip(sg.ip_permissions_egress);
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
            .about("Simple utility to help add and remove permissions quickly from AWS security groups")
            .author("Jonathan Constantinides <jonleecon@gmail.com>")
            .arg(Arg::with_name("list")
              .short("l")
              .long("list")
              .help("List information"))
            .arg(Arg::with_name("security-group")
              .long("sg")
              .value_name("SECURITY_GROUP")
              .help("Set specific security group"))
            .get_matches();

    let get_rules = || {
      let mut rules: HashMap<String, Vec<Port>> = HashMap::new();
      let mut rdr = csv::Reader::from_file(FILE_NAME).unwrap();
      for record in rdr.decode() {
            let (name, protocol, port): (String, String, usize) = record.unwrap();
            let entry_vector = rules.entry(name).or_insert(Vec::new());
            entry_vector.push(Port::new(protocol, port));
        }
    };

    let get_external_ip = || {
      let name = Name::from_str("myip.opendns.com.").unwrap();
      let client = SyncClient::new(
        UdpClientConnection::new(
          OPEN_DNS_ADDRESS.parse().unwrap()
        ).unwrap()
      );
      let response: Message = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

      if let &RData::A(ref ip) = response.answers()[0].rdata() {
        let mut set_str: Vec<String> = vec![];
        for i in &ip.octets() {
          // let a = i.to_string();
          set_str.push(i.to_string());
        }
        set_str;
      }
      else {
        // bail!("Unexpected Result")
      }
    };
    // print_definitions(&rules);

    let client = Ec2Client::new(
      default_tls_client().unwrap(),
      DefaultCredentialsProvider::new().unwrap(),
      Region::UsWest2
    );

    let print_securitygroups = || {
      let describe_security_group_request: DescribeSecurityGroupsRequest = Default::default();
      let output = client.describe_security_groups(&describe_security_group_request).unwrap();
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

    if matches.is_present("list") {
      if let Some(sg) = matches.value_of("security-group") {
        let describe_security_group_request = DescribeSecurityGroupsRequest {
          group_ids: Some(vec![sg.to_string()]),
          ..Default::default()
        };

        let security_groups = client
          .describe_security_groups(&describe_security_group_request).unwrap()
          .security_groups.unwrap();

        for security_group in security_groups {
          print_security_group(security_group);
        }
      }
      else {
        print_securitygroups();
      }
    }

    Ok(())
}
