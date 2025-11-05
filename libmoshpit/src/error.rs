use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("incomplete data")]
    Incomplete,
}
