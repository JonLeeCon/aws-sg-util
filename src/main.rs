#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate csv;

mod errors {
    error_chain!{}
}

use errors::*;
use std::collections::HashMap;

const FILE_NAME: &'static str = "./config/ports.csv";

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

fn setup_definitions(rules: &mut HashMap<String, Vec<Port>>) {
  let mut rdr = csv::Reader::from_file(FILE_NAME).unwrap();

  for record in rdr.decode() {
        let (name, protocol, port): (String, String, usize) = record.unwrap();
        let entry_vector = rules.entry(name).or_insert(Vec::new());

        entry_vector.push(Port::new(protocol, port));
    }
}

fn print_definitions(rules: &HashMap<String, Vec<Port>>) {
  for (name, port) in rules {
        println!("{}: {:?}", name, port);
    }
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
    let mut rules: HashMap<String, Vec<Port>> = HashMap::new();
    setup_definitions(&mut rules);
    print_definitions(&rules);

    Ok(())
}
