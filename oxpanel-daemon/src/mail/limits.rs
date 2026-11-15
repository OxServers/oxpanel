//! Email limits: the host's defaults and an account's two layers.
//!
//! Every account has four email limits: mailboxes, the largest mailbox,
//! and recipients per clock hour for the whole account (its mailboxes and
//! its sites) and for one mailbox. Each is resolved through three places,
//! the first that says something winning:
//!
//! 1. the account's **account layer** (staff's override for this account),
//! 2. the account's **plan layer** (what a panel copies from the account's
//!    plan when the plan is assigned),
//! 3. the **host default** (`/var/lib/oxpanel/mail/defaults.json`, changed
//!    with `SetMailDefaults`; until then the built-in values below, which
//!    `OXPANEL_MAIL_*` in the environment may change).
//!
//! A layer's setting is `inherit` (say nothing: the next place decides),
//! a value, or `unlimited`. A host default is a value or `unlimited`, never
//! `inherit`. "Unlimited" therefore only ever comes from an explicit
//! `unlimited`: a field left out of a request is `inherit`, and moving an
//! account to a plan without email limits makes its plan layer `inherit`,
//! i.e. the host default. An account that follows the host default follows
//! it live: the policy map is rendered from the resolved limits, so a change
//! of the default reaches every such account at once.
//!
//! **Migration from engine 0.3.0**, whose account record held one optional
//! value per limit (absent: the host default, 0: unlimited) and whose host
//! defaults were 500 / 200 recipients per hour: such a record is read as an
//! account layer (absent → inherit, 0 → unlimited, n → n), except that an
//! account holding exactly the old default sending limits (500 and 200)
//! follows the host default again, for those two limits, and an account
//! holding exactly all the old defaults (0, 0, 500, 200) follows it for all
//! four. The record is converted when read and written in the new form the
//! next time it changes; nothing else is rewritten.

use serde::{Deserialize, Serialize};

use super::config::MailConfig;
use super::MIN_QUOTA_BYTES;
use crate::error::{Error, Result};

/// The most mailboxes a limit may name.
pub const MAX_MAILBOXES: u64 = 100_000;
/// The largest mailbox a limit may name (1 PiB).
pub const MAX_MAILBOX_BYTES: u64 = 1 << 50;
/// The most recipients per hour a limit may name.
pub const MAX_PER_HOUR: u64 = 1_000_000;

/// Built-in host defaults: recipients per hour for an account and for one
/// mailbox. Mailboxes and mailbox size are unlimited.
pub const BUILTIN_RATE_ACCOUNT: u64 = 30;
pub const BUILTIN_RATE_MAILBOX: u64 = 20;

/// Engine 0.3.0's host defaults (for the migration).
const OLD_RATE_ACCOUNT: u32 = 500;
const OLD_RATE_MAILBOX: u32 = 200;

/// One limit as set in a layer or as a host default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "value")]
pub enum Setting {
    /// Say nothing: the next place decides.
    #[default]
    Inherit,
    Value(u64),
    Unlimited,
}

/// The four limits of one layer (or of the host defaults).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Layer {
    pub max_mailboxes: Setting,
    pub max_mailbox_bytes: Setting,
    pub rate_account: Setting,
    pub rate_mailbox: Setting,
}

/// Which limit (field names in errors, bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    MaxMailboxes,
    MaxMailboxBytes,
    RateAccount,
    RateMailbox,
}

impl Which {
    pub const ALL: [Which; 4] = [
        Which::MaxMailboxes,
        Which::MaxMailboxBytes,
        Which::RateAccount,
        Which::RateMailbox,
    ];

    /// The API's name of the limit.
    pub fn field(self) -> &'static str {
        match self {
            Which::MaxMailboxes => "max_mailboxes",
            Which::MaxMailboxBytes => "max_mailbox_bytes",
            Which::RateAccount => "max_messages_per_hour_account",
            Which::RateMailbox => "max_messages_per_hour_mailbox",
        }
    }

    fn bounds(self) -> (u64, u64) {
        match self {
            Which::MaxMailboxes => (1, MAX_MAILBOXES),
            Which::MaxMailboxBytes => (MIN_QUOTA_BYTES, MAX_MAILBOX_BYTES),
            Which::RateAccount | Which::RateMailbox => (1, MAX_PER_HOUR),
        }
    }
}

impl Layer {
    pub fn get(&self, w: Which) -> Setting {
        match w {
            Which::MaxMailboxes => self.max_mailboxes,
            Which::MaxMailboxBytes => self.max_mailbox_bytes,
            Which::RateAccount => self.rate_account,
            Which::RateMailbox => self.rate_mailbox,
        }
    }

    pub fn set(&mut self, w: Which, s: Setting) {
        match w {
            Which::MaxMailboxes => self.max_mailboxes = s,
            Which::MaxMailboxBytes => self.max_mailbox_bytes = s,
            Which::RateAccount => self.rate_account = s,
            Which::RateMailbox => self.rate_mailbox = s,
        }
    }

    /// Every value within its bounds.
    pub fn validate(&self) -> Result<()> {
        for w in Which::ALL {
            if let Setting::Value(v) = self.get(w) {
                let (lo, hi) = w.bounds();
                if !(lo..=hi).contains(&v) {
                    return Err(Error::invalid(
                        w.field(),
                        format!("must be {lo} to {hi}, or unlimited, or inherit"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// A host default: every limit a value or unlimited.
    pub fn validate_defaults(&self) -> Result<()> {
        self.validate()?;
        for w in Which::ALL {
            if self.get(w) == Setting::Inherit {
                return Err(Error::invalid(
                    w.field(),
                    "a host default is a value or unlimited",
                ));
            }
        }
        Ok(())
    }

    /// `self` with each `inherit` of `update` keeping `self`'s setting.
    #[must_use]
    pub fn merged(&self, update: &Layer) -> Layer {
        let mut out = *self;
        for w in Which::ALL {
            let s = update.get(w);
            if s != Setting::Inherit {
                out.set(w, s);
            }
        }
        out
    }
}

/// The built-in host defaults, as the environment may change them
/// (`OXPANEL_MAIL_RATE_*`, `OXPANEL_MAIL_MAX_*`; 0 there is unlimited).
pub fn builtin(cfg: &MailConfig) -> Layer {
    let s = |v: u64| {
        if v == 0 {
            Setting::Unlimited
        } else {
            Setting::Value(v)
        }
    };
    Layer {
        max_mailboxes: s(u64::from(cfg.max_mailboxes)),
        max_mailbox_bytes: s(cfg.max_mailbox_bytes),
        rate_account: s(u64::from(cfg.rate_account)),
        rate_mailbox: s(u64::from(cfg.rate_mailbox)),
    }
}

/// Where an effective limit comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    HostDefault,
    Plan,
    Account,
}

/// One effective limit: `None` = unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub value: Option<u64>,
    pub source: Source,
}

impl Effective {
    /// As the policy map and the older API take it: 0 = unlimited.
    pub fn or_zero(self) -> u64 {
        self.value.unwrap_or(0)
    }

    pub fn or_zero_u32(self) -> u32 {
        u32::try_from(self.or_zero()).unwrap_or(u32::MAX)
    }
}

/// An account's limits, resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub plan: Layer,
    pub account: Layer,
    pub max_mailboxes: Effective,
    pub max_mailbox_bytes: Effective,
    pub rate_account: Effective,
    pub rate_mailbox: Effective,
}

impl Resolved {
    pub fn get(&self, w: Which) -> Effective {
        match w {
            Which::MaxMailboxes => self.max_mailboxes,
            Which::MaxMailboxBytes => self.max_mailbox_bytes,
            Which::RateAccount => self.rate_account,
            Which::RateMailbox => self.rate_mailbox,
        }
    }

    /// The flat form (0 = unlimited) the rest of the engine uses.
    pub fn flat(&self) -> super::Limits {
        super::Limits {
            max_mailboxes: self.max_mailboxes.or_zero_u32(),
            max_mailbox_bytes: self.max_mailbox_bytes.or_zero(),
            rate_account: self.rate_account.or_zero_u32(),
            rate_mailbox: self.rate_mailbox.or_zero_u32(),
        }
    }
}

fn effective(s: Setting, source: Source) -> Option<Effective> {
    match s {
        Setting::Inherit => None,
        Setting::Value(v) => Some(Effective {
            value: Some(v),
            source,
        }),
        Setting::Unlimited => Some(Effective {
            value: None,
            source,
        }),
    }
}

/// Resolve one limit: account layer, then plan layer, then the default.
fn one(defaults: &Layer, plan: &Layer, account: &Layer, w: Which) -> Effective {
    effective(account.get(w), Source::Account)
        .or_else(|| effective(plan.get(w), Source::Plan))
        .or_else(|| effective(defaults.get(w), Source::HostDefault))
        // A host default is never `inherit` (validated); should one be,
        // the built-in default applies, never "unlimited".
        .unwrap_or(Effective {
            value: Some(match w {
                Which::RateAccount => BUILTIN_RATE_ACCOUNT,
                Which::RateMailbox => BUILTIN_RATE_MAILBOX,
                Which::MaxMailboxes | Which::MaxMailboxBytes => 0,
            })
            .filter(|v| *v > 0),
            source: Source::HostDefault,
        })
}

pub fn resolve(defaults: &Layer, plan: &Layer, account: &Layer) -> Resolved {
    Resolved {
        plan: *plan,
        account: *account,
        max_mailboxes: one(defaults, plan, account, Which::MaxMailboxes),
        max_mailbox_bytes: one(defaults, plan, account, Which::MaxMailboxBytes),
        rate_account: one(defaults, plan, account, Which::RateAccount),
        rate_mailbox: one(defaults, plan, account, Which::RateMailbox),
    }
}

/// An engine 0.3.0 account record's values, as an account layer (see the
/// module documentation).
pub fn migrate_legacy(
    max_mailboxes: Option<u32>,
    max_mailbox_bytes: Option<u64>,
    rate_account: Option<u32>,
    rate_mailbox: Option<u32>,
) -> Layer {
    let s = |v: Option<u64>| match v {
        None => Setting::Inherit,
        Some(0) => Setting::Unlimited,
        Some(n) => Setting::Value(n),
    };
    let old_rates =
        rate_account == Some(OLD_RATE_ACCOUNT) && rate_mailbox == Some(OLD_RATE_MAILBOX);
    let all_old = old_rates && max_mailboxes == Some(0) && max_mailbox_bytes == Some(0);
    if all_old {
        return Layer::default();
    }
    Layer {
        max_mailboxes: s(max_mailboxes.map(u64::from)),
        max_mailbox_bytes: s(max_mailbox_bytes),
        rate_account: if old_rates {
            Setting::Inherit
        } else {
            s(rate_account.map(u64::from))
        },
        rate_mailbox: if old_rates {
            Setting::Inherit
        } else {
            s(rate_mailbox.map(u64::from))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(a: Setting, b: Setting, c: Setting, d: Setting) -> Layer {
        Layer {
            max_mailboxes: a,
            max_mailbox_bytes: b,
            rate_account: c,
            rate_mailbox: d,
        }
    }
    use Setting::{Inherit as I, Unlimited as U, Value as V};

    fn defaults() -> Layer {
        builtin(&MailConfig::default())
    }

    #[test]
    fn the_built_in_defaults_are_low_sending_limits() {
        assert_eq!(defaults(), layer(U, U, V(30), V(20)));
        assert!(defaults().validate_defaults().is_ok());
    }

    #[test]
    fn account_over_plan_over_default() {
        let d = defaults();
        let r = resolve(&d, &Layer::default(), &Layer::default());
        assert_eq!(
            r.rate_account,
            Effective {
                value: Some(30),
                source: Source::HostDefault
            }
        );
        assert_eq!(r.max_mailboxes.value, None);
        let plan = layer(V(5), I, V(1000), I);
        let r = resolve(&d, &plan, &Layer::default());
        assert_eq!(r.rate_account.value, Some(1000));
        assert_eq!(r.rate_account.source, Source::Plan);
        assert_eq!(r.rate_mailbox.value, Some(20));
        assert_eq!(r.rate_mailbox.source, Source::HostDefault);
        assert_eq!(r.max_mailboxes.source, Source::Plan);
        // A lower plan value wins too.
        let r = resolve(&d, &layer(I, I, V(10), I), &Layer::default());
        assert_eq!(r.rate_account.value, Some(10));
        let account = layer(I, I, U, V(7));
        let r = resolve(&d, &plan, &account);
        assert_eq!(r.rate_account.value, None);
        assert_eq!(r.rate_account.source, Source::Account);
        assert_eq!(r.rate_mailbox.value, Some(7));
        assert_eq!(r.max_mailboxes.value, Some(5));
        assert_eq!(r.flat().rate_account, 0);
        assert_eq!(r.flat().max_mailboxes, 5);
    }

    #[test]
    fn a_default_change_reaches_the_accounts_that_follow_it_only() {
        let mut d = defaults();
        let follower = resolve(&d, &Layer::default(), &Layer::default());
        let planned = resolve(&d, &layer(I, I, V(100), V(50)), &Layer::default());
        d.rate_account = V(60);
        let follower2 = resolve(&d, &Layer::default(), &Layer::default());
        let planned2 = resolve(&d, &layer(I, I, V(100), V(50)), &Layer::default());
        assert_eq!(follower.rate_account.value, Some(30));
        assert_eq!(follower2.rate_account.value, Some(60));
        assert_eq!(planned, planned2);
    }

    #[test]
    fn bounds_and_defaults_validation() {
        assert!(layer(V(0), I, I, I).validate().is_err());
        assert!(layer(I, V(1024), I, I).validate().is_err());
        assert!(layer(I, V(MIN_QUOTA_BYTES), I, I).validate().is_ok());
        assert!(layer(I, I, V(MAX_PER_HOUR + 1), I).validate().is_err());
        assert!(layer(V(MAX_MAILBOXES), U, V(1), V(MAX_PER_HOUR))
            .validate_defaults()
            .is_ok());
        assert!(layer(U, U, I, V(1)).validate_defaults().is_err());
    }

    #[test]
    fn merged_keeps_what_is_left_out() {
        let d = defaults();
        let m = d.merged(&layer(I, I, V(100), U));
        assert_eq!(m, layer(U, U, V(100), U));
        assert_eq!(d.merged(&Layer::default()), d);
    }

    #[test]
    fn legacy_records_migrate() {
        // Exactly the old defaults: the host default again, for everything.
        assert_eq!(
            migrate_legacy(Some(0), Some(0), Some(500), Some(200)),
            Layer::default()
        );
        // The old default sending limits with a mailbox limit: the rates follow the default.
        assert_eq!(
            migrate_legacy(Some(3), Some(0), Some(500), Some(200)),
            layer(V(3), U, I, I)
        );
        // Values set by staff or a plan are kept; 0 was unlimited.
        assert_eq!(
            migrate_legacy(Some(2), Some(0), Some(0), Some(0)),
            layer(V(2), U, U, U)
        );
        assert_eq!(
            migrate_legacy(None, None, Some(1000), Some(200)),
            layer(I, I, V(1000), V(200))
        );
        assert_eq!(migrate_legacy(None, None, None, None), Layer::default());
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    fn setting() -> impl Strategy<Value = Setting> {
        prop_oneof![
            Just(Setting::Inherit),
            Just(Setting::Unlimited),
            (1u64..=1_000_000).prop_map(Setting::Value),
        ]
    }

    fn a_layer() -> impl Strategy<Value = Layer> {
        (setting(), setting(), setting(), setting()).prop_map(|(a, b, c, d)| Layer {
            max_mailboxes: a,
            max_mailbox_bytes: b,
            rate_account: c,
            rate_mailbox: d,
        })
    }

    proptest! {
        /// A limit is unlimited only when the place it comes from says
        /// `unlimited` explicitly; it comes from the first place that says
        /// anything; and it is the value that place gives.
        #[test]
        fn unlimited_is_only_ever_explicit(d in a_layer(), plan in a_layer(), account in a_layer()) {
            let r = resolve(&d, &plan, &account);
            for w in Which::ALL {
                let e = r.get(w);
                let expected = [(account, Source::Account), (plan, Source::Plan), (d, Source::HostDefault)]
                    .into_iter()
                    .find(|(l, _)| l.get(w) != Setting::Inherit);
                if let Some((l, src)) = expected {
                    prop_assert_eq!(e.source, src);
                    match l.get(w) {
                        Setting::Unlimited => prop_assert_eq!(e.value, None),
                        Setting::Value(v) => prop_assert_eq!(e.value, Some(v)),
                        Setting::Inherit => unreachable!(),
                    }
                } else {
                    // Nowhere set (an invalid host default): never unlimited for sending.
                    prop_assert_eq!(e.source, Source::HostDefault);
                    if matches!(w, Which::RateAccount | Which::RateMailbox) {
                        prop_assert!(e.value.is_some());
                    }
                }
            }
        }

        /// A layer survives its record's round trip.
        #[test]
        fn layers_round_trip(l in a_layer()) {
            let text = serde_json::to_string(&l).unwrap();
            prop_assert_eq!(serde_json::from_str::<Layer>(&text).unwrap(), l);
        }
    }
}
