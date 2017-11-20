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
    -a, --add <DEFINED_SERVICE>       Add service
    -r, --remove <DEFINED_SERVICE>    Remove service
        --sg <SECURITY_GROUP>         Set specific security group
```

## Prerequisites
A Cargo/Rust setup for compiling

## Authors
Jonathan Constantinides <jonleecon@gmail.com>

## License
This project is licensed under the MIT License
