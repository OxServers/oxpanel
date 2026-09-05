//! Shared runtime context handed to the workflows.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::config::Config;
use crate::records::Store;
use crate::system::System;

/// Everything a workflow needs. Cheap to clone.
#[derive(Clone)]
pub struct Ctx {
    pub config: Arc<Config>,
    pub store: Store,
    pub sys: Arc<dyn System>,
    /// Serialises every mutating workflow. Provisioning touches shared,
    /// non-transactional resources (the passwd database, the Nginx config,
    /// systemd), so one mutation at a time is the only safe model.
    pub lock: Arc<Mutex<()>>,
    /// Whether SELinux is enabled on this host (labels are only managed if so).
    pub selinux: bool,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("config", &self.config)
            .field("selinux", &self.selinux)
            .finish_non_exhaustive()
    }
}

impl Ctx {
    pub fn new(config: Config, sys: Arc<dyn System>, selinux: bool) -> Self {
        let store = Store::new(&config);
        Self {
            config: Arc::new(config),
            store,
            sys,
            lock: Arc::new(Mutex::new(())),
            selinux,
        }
    }
}
