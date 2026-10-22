//! Published record ownership, registration updates and service announcements.

use super::{
    check_service_name_length, my_ip_interfaces_inner, schedule_register_resend, send_dns_outgoing,
    Command, Counter, DaemonEvent, InternalError, ReRun, UnregisterStatus, Zeroconf,
    ANNOUNCE_SECOND_DELAY_MILLIS, ANNOUNCE_SECOND_JITTER_MILLIS,
};
use crate::{
    dns_name::{names_equal, RrsetKey},
    dns_parser::{
        DnsIncoming, DnsOutgoing, DnsPointer, DnsRecordBox, DnsRecordExt, RRType, FLAGS_AA,
        FLAGS_QR_RESPONSE,
    },
    service_info::{registry_key, DnsRegistry, ServiceInfo, ServiceStatus},
};
use if_addrs::IfAddr;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

pub(super) type PublicationSnapshot = HashMap<u32, Vec<DnsRecordBox>>;

impl Zeroconf {
    pub(super) fn replace_registration(&mut self, mut info: ServiceInfo) {
        if let Err(error) = info.validate_records() {
            self.notify_monitors(DaemonEvent::Error(error));
            return;
        }
        if let Err(error) = check_service_name_length(info.get_type(), self.service_name_len_max) {
            self.notify_monitors(DaemonEvent::Error(error));
            return;
        }
        if info.is_addr_auto() {
            for intf in self.selected_intfs(my_ip_interfaces_inner(true, self.include_apple_p2p)) {
                info.insert_ipaddr(&intf);
            }
        }
        let fullname = registry_key(info.get_fullname());
        if let Some(previous) = self.my_services.get(&fullname) {
            for index in self.my_intfs.keys() {
                info.set_status(*index, previous.get_status(*index));
            }
            let changes_host = !names_equal(previous.get_hostname(), info.get_hostname());
            let waits_for_host = changes_host
                && info.requires_probe()
                && self.my_intfs.iter().any(|(index, intf)| {
                    let eligible = !info.get_addrs_on_my_intf_v4(intf).is_empty()
                        || !info.get_addrs_on_my_intf_v6(intf).is_empty();
                    eligible
                        && !self.dns_registry_map.get(index).is_some_and(|registry| {
                            registry.is_claimed(registry.resolve_name(info.get_hostname()))
                        })
                });
            if waits_for_host {
                self.pending_registrations.insert(fullname, info);
                self.reconcile_registries();
                return;
            }
        }
        let before = self.publication_snapshot();
        self.pending_registrations.remove(&fullname);
        self.my_services.insert(fullname, info);
        self.reconcile_registries();
        self.finish_publication_change(before, true);
    }

    pub(super) fn remove_registration(
        &mut self,
        fullname: String,
        repeating: bool,
    ) -> UnregisterStatus {
        let fullname = registry_key(&fullname);
        if !self.my_services.contains_key(&fullname) {
            return UnregisterStatus::NotFound;
        }
        let before = self.publication_snapshot();
        self.pending_registrations.remove(&fullname);
        self.my_services.remove(&fullname);
        self.cancel_registration_resends(&fullname);
        self.reconcile_registries();
        self.finish_publication_change(before, !repeating);
        self.increase_counter(Counter::Unregister, 1);
        UnregisterStatus::OK
    }

    pub(super) fn reconcile_registries(&mut self) {
        let indexes: HashSet<_> = self.my_intfs.keys().copied().collect();
        let published = &self.my_services;
        self.pending_registrations
            .retain(|name, _| published.contains_key(name));
        for service in self
            .my_services
            .values_mut()
            .chain(self.pending_registrations.values_mut())
        {
            service.retain_statuses(&indexes);
        }
        let services = &self.my_services;
        self.retransmissions.retain(|rerun| match &rerun.command {
            Command::RegisterResend(name, index) => {
                indexes.contains(index) && services.contains_key(&registry_key(name))
            }
            Command::UnregisterResend(_, index, _) => indexes.contains(index),
            _ => true,
        });
        self.delayed_responses
            .retain(|response| indexes.contains(&response.if_index));
        self.dns_registry_map
            .retain(|index, _| indexes.contains(index));
        let services: Vec<_> = self.my_services.values().collect();
        let pending_hosts: Vec<_> = self.pending_registrations.values().collect();
        let now = Instant::now();
        for (index, intf) in &self.my_intfs {
            self.dns_registry_map
                .entry(*index)
                .or_insert_with(DnsRegistry::new)
                .reconcile_publication(&services, &pending_hosts, intf, now);
        }
        for service in self.my_services.values_mut() {
            for (index, registry) in &self.dns_registry_map {
                if !registry.is_claimed(registry.resolve_name(service.get_fullname()))
                    || !registry.is_claimed(registry.resolve_name(service.get_hostname()))
                {
                    service.set_status(*index, ServiceStatus::Probing);
                }
            }
        }
    }

    pub(super) fn commit_ready_registrations(&mut self) {
        let ready: Vec<_> = self
            .pending_registrations
            .iter()
            .filter(|(_, service)| {
                self.my_intfs.iter().all(|(index, intf)| {
                    let eligible = !service.get_addrs_on_my_intf_v4(intf).is_empty()
                        || !service.get_addrs_on_my_intf_v6(intf).is_empty();
                    !eligible
                        || self.dns_registry_map.get(index).is_some_and(|registry| {
                            registry.is_claimed(registry.resolve_name(service.get_hostname()))
                        })
                })
            })
            .map(|(name, _)| name.clone())
            .collect();
        if ready.is_empty() {
            return;
        }
        let before = self.publication_snapshot();
        for name in ready {
            if let Some(mut service) = self.pending_registrations.remove(&name) {
                if let Some(previous) = self.my_services.get(&name) {
                    for index in self.my_intfs.keys() {
                        service.set_status(*index, previous.get_status(*index));
                    }
                }
                self.my_services.insert(name, service);
            }
        }
        self.reconcile_registries();
        self.finish_publication_change(before, true);
    }

    pub(super) fn publication_snapshot(&self) -> PublicationSnapshot {
        let mut snapshot = HashMap::new();
        for (index, registry) in &self.dns_registry_map {
            if !self.my_intfs.contains_key(index) {
                continue;
            }
            let mut records = Vec::new();
            for service in self.my_services.values() {
                let fullname = registry.resolve_name(service.get_fullname());
                let hostname = registry.resolve_name(service.get_hostname());
                for record in registry.records_for_name(hostname) {
                    push_record(&mut records, record.clone());
                }
                if !registry.is_claimed(fullname) || !registry.is_claimed(hostname) {
                    continue;
                }
                for record in registry.records_for_name(fullname) {
                    push_record(&mut records, record.clone());
                }
                for record in service.ptr_records(fullname) {
                    push_record(&mut records, record.boxed());
                }
            }
            snapshot.insert(*index, records);
        }
        snapshot
    }

    pub(super) fn finish_publication_change(
        &mut self,
        before: PublicationSnapshot,
        repeat_goodbyes: bool,
    ) {
        let after = self.publication_snapshot();
        self.prune_goodbye_retries(&after);
        let indexes: HashSet<_> = before.keys().chain(after.keys()).copied().collect();
        for index in indexes {
            let previous = before.get(&index).map(Vec::as_slice).unwrap_or(&[]);
            let current = after.get(&index).map(Vec::as_slice).unwrap_or(&[]);
            let (withdrawals, updates, changed) = publication_delta(previous, current);
            self.delayed_responses.retain(|response| {
                response.if_index != index
                    || (!current.is_empty()
                        && !response
                            .out
                            .answers()
                            .iter()
                            .chain(response.out.additionals())
                            .any(|record| changed.contains(&RrsetKey::new(record.as_ref()))))
            });
            if !self.my_intfs.contains_key(&index) {
                continue;
            }
            for is_ipv4 in [true, false] {
                let intf = &self.my_intfs[&index];
                let available = if is_ipv4 {
                    self.ipv4_sock.is_some() && intf.next_ifaddr_v4().is_some()
                } else {
                    self.ipv6_sock.is_some() && intf.next_ifaddr_v6().is_some()
                };
                if !available {
                    continue;
                }
                if !withdrawals.is_empty() {
                    let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
                    for record in &withdrawals {
                        let mut goodbye = record.clone();
                        goodbye.get_record_mut().set_ttl(0);
                        goodbye
                            .get_record_mut()
                            .set_cache_flush(record.get_type() != RRType::PTR);
                        out.add_answer_box(goodbye);
                    }
                    let packets = self.send_publication_packet(index, is_ipv4, &out);
                    if repeat_goodbyes {
                        for packet in packets {
                            if self.retransmissions.iter().any(|rerun| {
                                matches!(&rerun.command, Command::UnregisterResend(existing, current_index, current_family)
                                    if existing == &packet && *current_index == index && *current_family == is_ipv4)
                            }) {
                                continue;
                            }
                            self.add_retransmission(
                                Instant::now() + Duration::from_millis(120),
                                Command::UnregisterResend(packet, index, is_ipv4),
                            );
                        }
                    }
                }
                if updates.is_empty() {
                    continue;
                }
                let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
                for record in &updates {
                    let mut answer = record.clone();
                    answer
                        .get_record_mut()
                        .set_cache_flush(record.get_type() != RRType::PTR);
                    out.add_answer_box(answer);
                }
                self.dns_registry_map
                    .get_mut(&index)
                    .unwrap()
                    .apply_multicast_rate_limit(&mut out, Instant::now(), is_ipv4);
                let sent = out.answers_count() > 0
                    && !self
                        .send_publication_packet(index, is_ipv4, &out)
                        .is_empty();
                self.record_publication_update(index, &updates, false);
                if sent {
                    self.record_publication_update(index, out.answers(), true);
                }
            }
        }
    }

    /// Keeps withdrawals that still apply, including unrelated records in mixed packets.
    fn prune_goodbye_retries(&mut self, current: &PublicationSnapshot) {
        let queued = std::mem::take(&mut self.retransmissions);
        for rerun in queued {
            let ReRun { next_time, command } = rerun;
            let (packet, index, is_ipv4) = match command {
                Command::UnregisterResend(packet, index, is_ipv4) => (packet, index, is_ipv4),
                command => {
                    self.retransmissions.push(ReRun { next_time, command });
                    continue;
                }
            };
            let Some(intf) = self.my_intfs.get(&index) else {
                continue;
            };
            let records = current.get(&index).map(Vec::as_slice).unwrap_or(&[]);
            let Ok(incoming) = DnsIncoming::new(packet.clone(), intf.into()) else {
                self.retransmissions.push(ReRun {
                    next_time,
                    command: Command::UnregisterResend(packet, index, is_ipv4),
                });
                continue;
            };
            let withdrawn: Vec<_> = incoming.all_records().collect();
            let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
            for mut record in withdrawn
                .iter()
                .filter(|old| {
                    !records.iter().any(|published| {
                        if old.get_type() == RRType::PTR {
                            old.matches(published.as_ref())
                        } else {
                            RrsetKey::new(old.as_ref()) == RrsetKey::new(published.as_ref())
                        }
                    })
                })
                .cloned()
            {
                // Parsing a TTL-zero goodbye applies the receiver's one-second grace.
                record.get_record_mut().set_ttl(0);
                out.add_answer_box(record);
            }
            if out.answers_count() == withdrawn.len() {
                self.retransmissions.push(ReRun {
                    next_time,
                    command: Command::UnregisterResend(packet, index, is_ipv4),
                });
            } else if out.answers_count() > 0 {
                if let Some(packets) =
                    out.to_complete_data_on_wire(intf.max_packet_size(is_ipv4), is_ipv4)
                {
                    for packet in packets {
                        self.retransmissions.push(ReRun {
                            next_time,
                            command: Command::UnregisterResend(packet, index, is_ipv4),
                        });
                    }
                }
            }
        }
    }

    fn send_publication_packet(
        &self,
        index: u32,
        is_ipv4: bool,
        out: &DnsOutgoing,
    ) -> Vec<Vec<u8>> {
        let Some(intf) = self.my_intfs.get(&index) else {
            return Vec::new();
        };
        let socket = if is_ipv4 {
            &self.ipv4_sock
        } else {
            &self.ipv6_sock
        };
        let Some(socket) = socket else {
            return Vec::new();
        };
        match send_dns_outgoing(out, intf, &socket.pktinfo, self.port, None, None) {
            Ok(packets) => packets,
            Err(InternalError::IntfAddrInvalid(address)) => {
                let _ = self.send_cmd_to_self(Command::InvalidIntfAddrs(HashSet::from([address])));
                Vec::new()
            }
        }
    }

    fn record_publication_update(&mut self, index: u32, records: &[DnsRecordBox], sent: bool) {
        let Some(registry) = self.dns_registry_map.get(&index) else {
            return;
        };
        let mut affected = Vec::new();
        for (key, service) in &mut self.my_services {
            let fullname = registry.resolve_name(service.get_fullname());
            let hostname = registry.resolve_name(service.get_hostname());
            if !registry.is_claimed(fullname) || !registry.is_claimed(hostname) {
                continue;
            }
            let related = records.iter().any(|record| {
                names_equal(record.get_name(), fullname)
                    || (service.get_status(index) == ServiceStatus::Announced
                        && names_equal(record.get_name(), hostname))
                    || record
                        .any()
                        .downcast_ref::<DnsPointer>()
                        .is_some_and(|ptr| names_equal(ptr.alias(), fullname))
            });
            if related {
                let fullname = fullname.to_string();
                if sent {
                    service.set_status(index, ServiceStatus::Announced);
                }
                affected.push((key.clone(), fullname));
            }
        }
        for (key, fullname) in affected {
            let next_time = Instant::now()
                + Duration::from_millis(
                    ANNOUNCE_SECOND_DELAY_MILLIS + fastrand::u64(0..ANNOUNCE_SECOND_JITTER_MILLIS),
                );
            schedule_register_resend(&mut self.retransmissions, &key, index, next_time);
            if sent {
                let addresses: Vec<_> =
                    self.my_intfs[&index].addrs.iter().map(IfAddr::ip).collect();
                self.notify_monitors(DaemonEvent::Announce(fullname, format!("{addresses:?}")));
            }
        }
    }

    fn cancel_registration_resends(&mut self, fullname: &str) {
        self.retransmissions.retain(|rerun| match &rerun.command {
            Command::RegisterResend(name, _) => registry_key(name) != fullname,
            _ => true,
        });
    }
}

fn push_record(records: &mut Vec<DnsRecordBox>, record: DnsRecordBox) {
    if !records
        .iter()
        .any(|existing| existing.matches(record.as_ref()))
    {
        records.push(record);
    }
}

fn publication_delta(
    previous: &[DnsRecordBox],
    current: &[DnsRecordBox],
) -> (Vec<DnsRecordBox>, Vec<DnsRecordBox>, HashSet<RrsetKey>) {
    let group = |records: &[DnsRecordBox]| -> HashMap<RrsetKey, Vec<DnsRecordBox>> {
        let mut groups = HashMap::<_, Vec<_>>::new();
        for record in records {
            groups
                .entry(RrsetKey::new(record.as_ref()))
                .or_default()
                .push(record.clone());
        }
        groups
    };
    let old_groups = group(previous);
    let new_groups = group(current);
    let withdrawals: Vec<_> = previous
        .iter()
        .filter(|old| {
            if old.get_type() == RRType::PTR {
                !current.iter().any(|new| old.matches(new.as_ref()))
            } else {
                !new_groups.contains_key(&RrsetKey::new(old.as_ref()))
            }
        })
        .cloned()
        .collect();
    let mut updates = Vec::new();
    for (key, records) in new_groups {
        if key.rr_type == RRType::PTR {
            updates.extend(records.into_iter().filter(|record| {
                !previous.iter().any(|old| {
                    old.matches(record.as_ref())
                        && old.get_record().get_ttl() == record.get_record().get_ttl()
                })
            }));
        } else {
            let unchanged = old_groups.get(&key).is_some_and(|old| {
                old.len() == records.len()
                    && records.iter().all(|record| {
                        old.iter().any(|old| {
                            old.matches(record.as_ref())
                                && old.get_record().get_ttl() == record.get_record().get_ttl()
                        })
                    })
            });
            if !unchanged {
                updates.extend(records);
            }
        }
    }
    let changed = withdrawals
        .iter()
        .chain(&updates)
        .map(|record| RrsetKey::new(record.as_ref()))
        .collect();
    (withdrawals, updates, changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns_parser::{DnsAddress, InterfaceId, CLASS_IN, MAX_PKT_DEFAULT},
        service_info::MyIntf,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn address(last: u8) -> DnsRecordBox {
        DnsAddress::new(
            "shared.local.",
            RRType::A,
            CLASS_IN,
            120,
            Ipv4Addr::new(127, 0, 0, last).into(),
            InterfaceId {
                name: "loopback".to_string(),
                index: 1,
            },
        )
        .boxed()
    }

    fn pointer(name: &str) -> DnsRecordBox {
        DnsPointer::new(
            name,
            RRType::PTR,
            CLASS_IN,
            4500,
            "instance._test._tcp.local.".to_string(),
        )
        .boxed()
    }

    #[test]
    fn address_removal_reannounces_surviving_complete_rrset() {
        let (withdrawals, updates, _) = publication_delta(&[address(1), address(2)], &[address(2)]);
        assert!(withdrawals.is_empty());
        assert_eq!(updates.len(), 1);
        assert!(updates[0].matches(address(2).as_ref()));
    }

    #[test]
    fn last_address_owner_withdraws_rrset() {
        let (withdrawals, updates, _) = publication_delta(&[address(1)], &[]);
        assert_eq!(withdrawals.len(), 1);
        assert!(updates.is_empty());
    }

    #[test]
    fn subtype_removal_preserves_parent_pointer() {
        let parent = "_test._tcp.local.";
        let subtype = "_printer._sub._test._tcp.local.";
        let (withdrawals, updates, _) =
            publication_delta(&[pointer(parent), pointer(subtype)], &[pointer(parent)]);
        assert_eq!(withdrawals.len(), 1);
        assert_eq!(withdrawals[0].get_name(), subtype);
        assert!(updates.is_empty());
    }

    #[test]
    fn ttl_change_updates_without_withdrawing_record() {
        let old = address(1);
        let mut current = old.clone();
        current.get_record_mut().set_ttl(60);
        let (withdrawals, updates, _) = publication_delta(&[old], &[current]);
        assert!(withdrawals.is_empty());
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].get_record().get_ttl(), 60);
    }

    #[test]
    fn staged_shared_hostname_addresses_wait_for_commit_on_every_link() {
        use super::super::lifecycle_tests::{daemon, service, unregister};
        use if_addrs::Ifv4Addr;

        let (mut daemon, first_link) = daemon();
        let second_link = first_link + 100_000;
        let second = MyIntf {
            index: second_link,
            name: "second-link".to_string(),
            max_packet_size_v4: MAX_PKT_DEFAULT,
            max_packet_size_v6: MAX_PKT_DEFAULT,
            addrs: HashSet::from([IfAddr::V4(Ifv4Addr {
                ip: Ipv4Addr::new(10, 92, 0, 1),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                broadcast: None,
                prefixlen: 24,
            })]),
        };
        daemon.my_intfs.insert(second_link, second);
        let shared = service("shared", "b.local.", "127.0.0.1", "A");
        let original = service("moving", "a.local.", "127.0.0.1,10.92.0.1", "A");
        let fullname = registry_key(original.get_fullname());
        daemon
            .my_services
            .insert(registry_key(shared.get_fullname()), shared);
        daemon
            .my_services
            .insert(fullname.clone(), original.clone());
        daemon.reconcile_registries();
        // Establish the fixture on two links without using a nonexistent OS interface.
        for registry in daemon.dns_registry_map.values_mut() {
            let names: Vec<_> = registry.probing.keys().cloned().collect();
            for name in names {
                registry.complete_probe(&name).unwrap();
            }
        }

        for host in ["b.local.", "c.local.", "b.local."] {
            daemon.register_service(service("moving", host, "127.0.0.2,10.92.0.1", "B"));
            assert_eq!(daemon.pending_registrations.len(), 1);
            assert_eq!(daemon.my_services[&fullname].get_hostname(), "a.local.");
            assert_eq!(
                daemon.dns_registry_map[&first_link].host_addresses("b.local."),
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
            );
        }
        daemon.register_service(original);
        assert!(daemon.pending_registrations.is_empty());
        assert!(!daemon.dns_registry_map[&second_link]
            .probing
            .contains_key("b.local."));
        assert_eq!(
            daemon.dns_registry_map[&first_link].host_addresses("b.local."),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );

        daemon.register_service(service("moving", "b.local.", "127.0.0.3,10.92.0.1", "C"));
        daemon
            .dns_registry_map
            .get_mut(&second_link)
            .unwrap()
            .complete_probe("b.local.")
            .unwrap();
        daemon.reconcile_registries();
        assert!(daemon.dns_registry_map[&second_link].is_claimed("b.local."));
        assert_eq!(
            daemon.dns_registry_map[&first_link].host_addresses("b.local."),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        let before = daemon.publication_snapshot();
        daemon.commit_ready_registrations();
        assert!(daemon.pending_registrations.is_empty());
        assert_eq!(daemon.my_services[&fullname].get_hostname(), "b.local.");
        assert_eq!(
            daemon.dns_registry_map[&first_link].host_addresses("b.local."),
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))
            ]
        );
        let after = daemon.publication_snapshot();
        let (withdrawals, updates, _) =
            publication_delta(&before[&first_link], &after[&first_link]);
        let address_updates: Vec<_> = updates
            .iter()
            .filter(|record| {
                record.get_type() == RRType::A && names_equal(record.get_name(), "b.local.")
            })
            .collect();
        assert_eq!(address_updates.len(), 2);
        assert!(!withdrawals
            .iter()
            .any(|record| names_equal(record.get_name(), "b.local.")));
        unregister(&mut daemon, &fullname);
        unregister(&mut daemon, "shared._lifecycle._tcp.local.");
        assert!(daemon
            .dns_registry_map
            .values()
            .all(|registry| registry.active.is_empty() && registry.probing.is_empty()));
    }
}
