//! Opaque, delete-only access to the operating-system credential store.

use thiserror::Error;

/// A locator that can only be consumed by [`delete_only`].
///
/// It intentionally implements neither `Clone` nor `Debug` and exposes none of
/// its source material.
pub struct DeleteOnlyLocator {
    service: String,
    username: String,
}

impl DeleteOnlyLocator {
    /// Construct one bounded exact credential locator.
    ///
    /// This workspace-private API is enforced by Cargo dependency allowlisting:
    /// only `kirje-store` depends directly on this unpublished crate.
    ///
    /// # Errors
    ///
    /// Rejects empty, NUL-containing, or excessively large components.
    pub fn new(service: &str, username: &str) -> Result<Self, DeleteError> {
        if service.is_empty()
            || username.is_empty()
            || service.len() > 255
            || username.len() > 1024
            || service.contains('\0')
            || username.contains('\0')
        {
            return Err(DeleteError::InvalidLocator);
        }
        Ok(Self {
            service: service.to_owned(),
            username: username.to_owned(),
        })
    }
}

/// Stable failure categories for the delete-only boundary.
#[derive(Debug, Error)]
pub enum DeleteError {
    /// The sealed locator is outside the bounded keyring contract.
    #[error("credential locator is invalid")]
    InvalidLocator,
    /// The platform credential store could not complete deletion.
    #[error("credential store is unavailable")]
    BackendUnavailable,
}

/// Delete one credential without revealing whether it previously existed.
///
/// # Errors
///
/// Returns [`DeleteError::BackendUnavailable`] for every platform failure other
/// than the idempotent no-entry result.
#[allow(clippy::needless_pass_by_value)]
pub fn delete_only(locator: DeleteOnlyLocator) -> Result<(), DeleteError> {
    let entry = keyring::Entry::new(&locator.service, &locator.username)
        .map_err(|_| DeleteError::BackendUnavailable)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(DeleteError::BackendUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_shape_is_bounded_before_backend_access() {
        assert!(matches!(
            DeleteOnlyLocator::new("", "account"),
            Err(DeleteError::InvalidLocator)
        ));
        assert!(matches!(
            DeleteOnlyLocator::new("service", ""),
            Err(DeleteError::InvalidLocator)
        ));
        assert!(DeleteOnlyLocator::new("service", "account").is_ok());
    }
}
