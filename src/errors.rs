use failure::{Backtrace, Context, Fail};
use std::result;
use std::fmt;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    ctx: Context<ErrorKind>,
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.ctx.get_context()
    }
    pub fn missing_arg<T: AsRef<str>>(msg: T) -> Error {
        Error::from(ErrorKind::MissingRequiredArgError(msg.as_ref().to_string()))
    }
    pub fn incorrect_args<T: AsRef<str>>(msg: T) -> Error {
        Error::from(ErrorKind::IncorrectArgError(msg.as_ref().to_string()))
    }
    pub fn obtain_ip() -> Error {
        Error::from(ErrorKind::ObtainIpError)
    }
    pub fn invalid_ip() -> Error {
        Error::from(ErrorKind::InvalidIpFormatError)
    }
    pub fn config<T: AsRef<str>>(msg: T) -> Error {
        Error::from(ErrorKind::ConfigError(msg.as_ref().to_string()))
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    MissingRequiredArgError(String),
    IncorrectArgError(String),
    ObtainIpError,
    InvalidIpFormatError,
    ConfigError(String),
    #[doc(hidden)]
    __Nonexhaustive,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ErrorKind::MissingRequiredArgError(ref msg) => {
                write!(f, "missing required argument: '{}'", msg)
            }
            ErrorKind::IncorrectArgError(ref msg) => {
                write!(f, "incorrect usage of arguments: '{}'", msg)
            }
            ErrorKind::ObtainIpError => {
                write!(f, "unable to get external ip from dns request")
            }
            ErrorKind::InvalidIpFormatError => {
                write!(f, "invalid ip address format")
            }
            ErrorKind::ConfigError(ref msg) => {
                write!(f, "error loading config file: '{}'", msg)
            }
            ErrorKind::__Nonexhaustive => panic!("invalid error"),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error::from(Context::new(kind))
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(ctx: Context<ErrorKind>) -> Error {
        Error { ctx }
    }
}