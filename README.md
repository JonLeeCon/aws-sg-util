# aws-sg-util

Simple utility to help list, add, and remove permissions quickly from AWS security groups

## Usage
```
aws-sg-util [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -l, --list       List information
    -V, --version    Prints version information

OPTIONS:
    -a, --add <DEFINED_SERVICE>       Add service/port (number)
        --ip <IP_ADDRESS>             Set specific ip address
    -r, --remove <DEFINED_SERVICE>    Remove service/port (number)
        --sg <SECURITY_GROUP>         Set specific security group
```
## Getting Started
### Prerequisites
- A Cargo/Rust setup for compiling
- AWS CLI installed

### Setting Up
- Create folder called *config* in the same location as the final compiled binary
- Create a *ports.csv* with (include header) name, protocol, port in the newly created config folder
- Add any services(anything you want to use) and protocol(tcp/udp) + port combinations

## Authors
Jonathan Constantinides <jonleecon@gmail.com>

## License
This project is licensed under the MIT License
