//! The daemon's single error type and its mapping onto gRPC status codes.
//!
//! Every fallible operation in the crate returns [`Error`]. Internal details
//! (paths, command output, OS error text) are logged by the server layer and
//! deliberately *not* echoed back to the client except where the client needs
//! them to act (validation errors, `nginx -t` output).

use std::path::PathBuf;

use tonic::Status;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A request field failed validation. Safe to return verbatim.
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },

    #[error("tenant '{0}' already exists")]
    TenantExists(String),

    /// A tenant with this name exists but its recorded specification differs
    /// from the request, so the request cannot be treated as an idempotent replay.
    #[error("tenant '{0}' already exists with a different specification")]
    SpecMismatch(String),

    #[error("tenant '{0}' not found")]
    TenantNotFound(String),

    /// A POSIX user with this name exists but OxPanel did not create it.
    /// The daemon never modifies or deletes users it does not manage.
    #[error("user '{0}' exists but is not managed by OxPanel")]
    NotManaged(String),

    /// The tenant record exists but the tenant is still provisioning or being deleted.
    #[error("tenant '{0}' is not ready")]
    TenantNotReady(String),

    #[error("tenant '{0}' still owns virtual hosts; remove them first")]
    TenantHasVHosts(String),

    #[error("no free UID in range {min}..={max}")]
    UidExhausted { min: u32, max: u32 },

    #[error("virtual host '{0}' not found")]
    VHostNotFound(String),

    #[error("virtual host '{domain}' is owned by tenant '{owner}'")]
    VHostOwnedByOther { domain: String, owner: String },

    /// `nginx -t` rejected the generated configuration. The output is returned
    /// to the caller because it is needed to diagnose the problem.
    #[error("nginx rejected the configuration: {0}")]
    NginxInvalid(String),

    #[error("{program} exited with {status}")]
    CommandFailed {
        program: String,
        status: String,
        stderr: String,
    },

    #[error("{program} did not finish within {secs}s")]
    CommandTimeout { program: String, secs: u64 },

    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{op}: {source}")]
    Sys {
        op: &'static str,
        #[source]
        source: nix::Error,
    },

    #[error("corrupt record {path}: {reason}")]
    CorruptRecord { path: PathBuf, reason: String },

    #[error("peer is not authorised to use this API")]
    Unauthorised,

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Shorthand for an I/O error tagged with the operation and path.
    pub fn io(op: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            op,
            path: path.into(),
            source,
        }
    }

    /// Shorthand for a validation failure.
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            reason: reason.into(),
        }
    }

    /// True when the error is the caller's fault (safe to return in full).
    fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidInput { .. }
                | Self::TenantExists(_)
                | Self::SpecMismatch(_)
                | Self::TenantNotFound(_)
                | Self::NotManaged(_)
                | Self::TenantNotReady(_)
                | Self::TenantHasVHosts(_)
                | Self::UidExhausted { .. }
                | Self::VHostNotFound(_)
                | Self::VHostOwnedByOther { .. }
                | Self::NginxInvalid(_)
                | Self::Unauthorised
        )
    }
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        let message = if err.is_client_error() {
            err.to_string()
        } else {
            // Operational details stay in the daemon journal.
            "internal error; see the oxpanel-daemon journal".to_owned()
        };
        match err {
            Error::InvalidInput { .. } => Status::invalid_argument(message),
            Error::TenantExists(_) | Error::SpecMismatch(_) => Status::already_exists(message),
            Error::TenantNotFound(_) | Error::VHostNotFound(_) => Status::not_found(message),
            Error::NotManaged(_)
            | Error::TenantNotReady(_)
            | Error::TenantHasVHosts(_)
            | Error::VHostOwnedByOther { .. }
            | Error::NginxInvalid(_) => Status::failed_precondition(message),
            Error::UidExhausted { .. } => Status::resource_exhausted(message),
            Error::Unauthorised => Status::permission_denied(message),
            Error::CommandTimeout { .. } => Status::deadline_exceeded(message),
            Error::CommandFailed { .. }
            | Error::Io { .. }
            | Error::Sys { .. }
            | Error::CorruptRecord { .. }
            | Error::Internal(_) => Status::internal(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn client_errors_keep_their_message() {
        let s: Status = Error::invalid("username", "too short").into();
        assert_eq!(s.code(), Code::InvalidArgument);
        assert_eq!(s.message(), "invalid username: too short");
    }

    #[test]
    fn internal_errors_are_redacted() {
        let s: Status = Error::io(
            "write",
            "/etc/nginx/oxpanel.d/secret.conf",
            std::io::Error::other("disk on fire"),
        )
        .into();
        assert_eq!(s.code(), Code::Internal);
        assert!(!s.message().contains("secret"));
        assert!(!s.message().contains("disk"));
    }

    #[test]
    fn code_mapping() {
        let cases: Vec<(Error, Code)> = vec![
            (Error::TenantExists("a".into()), Code::AlreadyExists),
            (Error::SpecMismatch("a".into()), Code::AlreadyExists),
            (Error::TenantNotFound("a".into()), Code::NotFound),
            (Error::VHostNotFound("a".into()), Code::NotFound),
            (Error::NotManaged("root".into()), Code::FailedPrecondition),
            (Error::TenantNotReady("a".into()), Code::FailedPrecondition),
            (Error::TenantHasVHosts("a".into()), Code::FailedPrecondition),
            (Error::NginxInvalid("x".into()), Code::FailedPrecondition),
            (
                Error::UidExhausted { min: 1, max: 2 },
                Code::ResourceExhausted,
            ),
            (Error::Unauthorised, Code::PermissionDenied),
            (
                Error::CommandTimeout {
                    program: "p".into(),
                    secs: 1,
                },
                Code::DeadlineExceeded,
            ),
            (Error::Internal("x".into()), Code::Internal),
        ];
        for (err, code) in cases {
            let s: Status = err.into();
            assert_eq!(s.code(), code);
        }
    }
}
