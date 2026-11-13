//! `oxpanel-ctl dns …`: zones and records of DNS hosting.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use tonic::transport::Channel;

use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

use crate::emit;

#[derive(Subcommand, Debug)]
pub(crate) enum DnsCmd {
    /// Create a zone for a tenant (sites get one by themselves).
    ZoneCreate {
        zone: String,
        #[arg(long)]
        tenant: String,
    },
    /// List zones (without their records).
    ZoneList {
        #[arg(long, default_value = "")]
        tenant: String,
    },
    /// A zone with every record, the engine's (protected) ones included, and
    /// its DNSSEC state with the DS records for the registrar.
    ZoneShow {
        zone: String,
        #[arg(long)]
        tenant: String,
    },
    /// Delete a zone with all its records.
    ZoneDelete {
        zone: String,
        #[arg(long)]
        tenant: String,
    },
    /// Remove every record the tenant added (the engine's records stay).
    ZoneReset {
        zone: String,
        #[arg(long)]
        tenant: String,
    },
    /// Look at the zone from outside: delegation, DS at the parent, serials.
    ZoneCheck {
        zone: String,
        #[arg(long)]
        tenant: String,
    },
    /// Add a record.
    RecordAdd {
        zone: String,
        #[arg(long)]
        tenant: String,
        #[command(flatten)]
        record: RecordArgs,
    },
    /// Replace a record (by id) with new contents.
    RecordUpdate {
        zone: String,
        id: u64,
        #[arg(long)]
        tenant: String,
        #[command(flatten)]
        record: RecordArgs,
    },
    /// Remove a record (by id).
    RecordRemove {
        zone: String,
        id: u64,
        #[arg(long)]
        tenant: String,
    },
    /// Switch DNSSEC signing of a zone on or off.
    Dnssec {
        zone: String,
        state: OnOff,
        #[arg(long)]
        tenant: String,
        /// Switch off although the parent could not be checked for a DS record.
        #[arg(long)]
        force: bool,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub(crate) enum OnOff {
    On,
    Off,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub(crate) enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Caa,
    Ns,
}

#[derive(Args, Debug)]
pub(crate) struct RecordArgs {
    /// Relative to the zone: "@" for the apex, "www", "_dmarc", "*.dev".
    #[arg(long)]
    name: String,
    #[arg(long = "type", value_enum)]
    rtype: RecordType,
    /// Address, host name, text or CAA value (see `--value-file` for long text).
    #[arg(long, default_value = "", conflicts_with = "value_file")]
    value: String,
    /// Read the value from a file (a DKIM key, say); one trailing line break is dropped.
    #[arg(long)]
    value_file: Option<PathBuf>,
    /// Seconds; 0 = the zone's default.
    #[arg(long, default_value_t = 0)]
    ttl: u32,
    /// MX preference or SRV priority.
    #[arg(long, default_value_t = 0)]
    priority: u32,
    #[arg(long, default_value_t = 0)]
    weight: u32,
    #[arg(long, default_value_t = 0)]
    port: u32,
    #[arg(long, default_value_t = 0)]
    caa_flags: u32,
    /// issue, issuewild or iodef.
    #[arg(long, default_value = "")]
    caa_tag: String,
}

impl RecordArgs {
    fn into_pb(self) -> Result<pb::DnsRecord, tonic::Status> {
        let value = match &self.value_file {
            None => self.value,
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| tonic::Status::invalid_argument(format!("{}: {e}", p.display())))?
                .trim_end_matches(['\n', '\r'])
                .to_owned(),
        };
        let t = match self.rtype {
            RecordType::A => pb::DnsRecordType::A,
            RecordType::Aaaa => pb::DnsRecordType::Aaaa,
            RecordType::Cname => pb::DnsRecordType::Cname,
            RecordType::Mx => pb::DnsRecordType::Mx,
            RecordType::Txt => pb::DnsRecordType::Txt,
            RecordType::Srv => pb::DnsRecordType::Srv,
            RecordType::Caa => pb::DnsRecordType::Caa,
            RecordType::Ns => pb::DnsRecordType::Ns,
        };
        Ok(pb::DnsRecord {
            name: self.name,
            r#type: t.into(),
            ttl: self.ttl,
            value,
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            caa_flags: self.caa_flags,
            caa_tag: self.caa_tag,
            ..pb::DnsRecord::default()
        })
    }
}

fn type_name(t: i32) -> &'static str {
    pb::DnsRecordType::try_from(t).map_or("UNKNOWN", |t| match t {
        pb::DnsRecordType::A => "A",
        pb::DnsRecordType::Aaaa => "AAAA",
        pb::DnsRecordType::Cname => "CNAME",
        pb::DnsRecordType::Mx => "MX",
        pb::DnsRecordType::Txt => "TXT",
        pb::DnsRecordType::Srv => "SRV",
        pb::DnsRecordType::Caa => "CAA",
        pb::DnsRecordType::Ns => "NS",
        pb::DnsRecordType::Soa => "SOA",
        pb::DnsRecordType::Unspecified => "UNSPECIFIED",
    })
}

/// One record per line; the value comes last because it may contain spaces.
fn print_record(r: &pb::DnsRecord) {
    emit(&format!(
        "id={} name={} type={} ttl={} priority={} weight={} port={} caa={} protected={} origin={} value={}",
        r.id,
        r.name,
        type_name(r.r#type),
        r.ttl,
        r.priority,
        r.weight,
        r.port,
        if r.caa_tag.is_empty() {
            "-".to_owned()
        } else {
            format!("{}:{}", r.caa_flags, r.caa_tag)
        },
        r.protected,
        if r.origin.is_empty() { "-" } else { r.origin.as_str() },
        r.value
    ));
}

fn dnssec_name(z: &pb::DnsZone) -> &'static str {
    z.dnssec
        .as_ref()
        .map_or("off", |d| match pb::DnssecState::try_from(d.state) {
            Ok(pb::DnssecState::Signing) => "signing",
            Ok(pb::DnssecState::Signed) => "signed",
            _ => "off",
        })
}

fn print_zone(z: &pb::DnsZone, records: bool) {
    emit(&format!(
        "zone={} tenant={} automatic={} serial={} dnssec={} records={} sites={} created_at={}",
        z.zone,
        z.tenant,
        z.automatic,
        z.serial,
        dnssec_name(z),
        z.record_count,
        if z.sites.is_empty() {
            "-".to_owned()
        } else {
            z.sites.join(",")
        },
        z.created_at.as_ref().map_or(0, |t| t.seconds),
    ));
    if !records {
        return;
    }
    for r in &z.records {
        print_record(r);
    }
    if let Some(d) = &z.dnssec {
        for ds in &d.ds_records {
            emit(&format!("ds={ds}"));
        }
        for k in &d.dnskey_records {
            emit(&format!("dnskey={k}"));
        }
    }
}

pub(crate) async fn run_dns(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: DnsCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        DnsCmd::ZoneCreate { zone, tenant } => {
            let r = c
                .create_dns_zone(pb::CreateDnsZoneRequest { tenant, zone })
                .await?
                .into_inner();
            emit(&format!("created={}", r.created));
            if let Some(z) = &r.zone {
                print_zone(z, true);
            }
        }
        DnsCmd::ZoneList { tenant } => {
            let r = c
                .list_dns_zones(pb::ListDnsZonesRequest { tenant })
                .await?
                .into_inner();
            for z in &r.zones {
                print_zone(z, false);
            }
        }
        DnsCmd::ZoneShow { zone, tenant } => {
            let z = c
                .get_dns_zone(pb::GetDnsZoneRequest { tenant, zone })
                .await?
                .into_inner();
            print_zone(&z, true);
        }
        DnsCmd::ZoneDelete { zone, tenant } => {
            let r = c
                .delete_dns_zone(pb::DeleteDnsZoneRequest { tenant, zone })
                .await?
                .into_inner();
            emit(&format!("deleted={}", r.deleted));
        }
        DnsCmd::ZoneReset { zone, tenant } => {
            let z = c
                .reset_dns_zone(pb::ResetDnsZoneRequest { tenant, zone })
                .await?
                .into_inner();
            print_zone(&z, true);
        }
        DnsCmd::ZoneCheck { zone, tenant } => zone_check(c, zone, tenant).await?,
        other => return run_record(c, other).await,
    }
    Ok(ExitCode::SUCCESS)
}

async fn zone_check(
    c: &mut OxPanelEngineClient<Channel>,
    zone: String,
    tenant: String,
) -> Result<(), tonic::Status> {
    let r = c
        .check_dns_zone(pb::CheckDnsZoneRequest { tenant, zone })
        .await?
        .into_inner();
    let delegation =
        pb::DelegationState::try_from(r.delegation).map_or("UNKNOWN", |d| d.as_str_name());
    emit(&format!(
        "zone={} delegation={} nameservers_seen={} ds_checked={} ds_at_parent={} ds_matches={}",
        r.zone,
        delegation.trim_start_matches("DELEGATION_STATE_"),
        if r.nameservers_seen.is_empty() {
            "-".to_owned()
        } else {
            r.nameservers_seen.join(",")
        },
        r.ds_checked,
        r.ds_at_parent.len(),
        r.ds_matches
    ));
    for ds in &r.ds_at_parent {
        emit(&format!("parent_ds={ds}"));
    }
    for s in &r.serials {
        emit(&format!(
            "server={} serial={} status={}",
            s.server, s.serial, s.status
        ));
    }
    emit(&format!("guidance={}", r.guidance));
    Ok(())
}

/// The record commands and DNSSEC.
async fn run_record(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: DnsCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        DnsCmd::RecordAdd {
            zone,
            tenant,
            record,
        } => {
            let r = c
                .add_dns_record(pb::AddDnsRecordRequest {
                    tenant,
                    zone,
                    record: Some(record.into_pb()?),
                })
                .await?
                .into_inner();
            emit(&format!("changed={} serial={}", r.changed, r.serial));
            if let Some(rec) = &r.record {
                print_record(rec);
            }
        }
        DnsCmd::RecordUpdate {
            zone,
            id,
            tenant,
            record,
        } => {
            let r = c
                .update_dns_record(pb::UpdateDnsRecordRequest {
                    tenant,
                    zone,
                    id,
                    record: Some(record.into_pb()?),
                })
                .await?
                .into_inner();
            emit(&format!("changed={} serial={}", r.changed, r.serial));
            if let Some(rec) = &r.record {
                print_record(rec);
            }
        }
        DnsCmd::RecordRemove { zone, id, tenant } => {
            let r = c
                .remove_dns_record(pb::RemoveDnsRecordRequest { tenant, zone, id })
                .await?
                .into_inner();
            emit(&format!("removed={} serial={}", r.removed, r.serial));
        }
        DnsCmd::Dnssec {
            zone,
            state,
            tenant,
            force,
        } => {
            let z = c
                .set_dnssec(pb::SetDnssecRequest {
                    tenant,
                    zone,
                    enabled: matches!(state, OnOff::On),
                    force,
                })
                .await?
                .into_inner();
            print_zone(&z, true);
        }
        // The zone commands are handled by `run_dns`.
        _ => return Err(tonic::Status::internal("unexpected command")),
    }
    Ok(ExitCode::SUCCESS)
}

/// The DNS line of `host info`.
pub(crate) fn print_host_dns(d: &pb::DnsHostInfo) {
    emit(&format!(
        "dns={} dns_available={} dns_server_running={} dns_zones={} nameservers={} secondaries={} ipv4={} ipv6={} soa_contact={} default_ttl={} dns_server={}",
        d.enabled,
        d.available,
        d.server_running,
        d.zone_count,
        if d.nameservers.is_empty() { "-".to_owned() } else { d.nameservers.join(",") },
        if d.secondaries.is_empty() { "-".to_owned() } else { d.secondaries.join(",") },
        if d.ipv4.is_empty() { "-" } else { d.ipv4.as_str() },
        if d.ipv6.is_empty() { "-" } else { d.ipv6.as_str() },
        if d.soa_contact.is_empty() { "-" } else { d.soa_contact.as_str() },
        d.default_ttl,
        if d.server_version.is_empty() { "-".to_owned() } else { d.server_version.replace(' ', "_") },
    ));
    emit(&format!("dns_detail={}", d.detail));
    for w in &d.warnings {
        emit(&format!("dns_warning={w}"));
    }
}
