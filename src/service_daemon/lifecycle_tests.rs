use super::*;
use crate::service_info::registry_key;
use if_addrs::{IfOperStatus, Ifv4Addr};

pub(super) fn daemon() -> (Zeroconf, u32) {
    let mut daemon = super::tests::new_test_zeroconf();
    let loopback = my_ip_interfaces(true)
        .into_iter()
        .find(|intf| intf.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    let index = loopback.index.unwrap();
    daemon.my_intfs.retain(|key, _| *key == index);
    daemon.dns_registry_map.retain(|key, _| *key == index);
    daemon
        .my_intfs
        .get_mut(&index)
        .unwrap()
        .addrs
        .retain(|address| address.ip().is_ipv4());
    daemon.ipv6_sock = None;
    daemon.if_selections = vec![
        IfSelection {
            if_kind: IfKind::All,
            selected: false,
        },
        IfSelection {
            if_kind: IfKind::Name(loopback.name),
            selected: true,
        },
    ];
    (daemon, index)
}

pub(super) fn service(instance: &str, hostname: &str, address: &str, txt: &str) -> ServiceInfo {
    ServiceInfo::new(
        "_lifecycle._tcp.local.",
        instance,
        hostname,
        address,
        8080,
        &[("version", txt)][..],
    )
    .unwrap()
}

pub(super) fn finish(daemon: &mut Zeroconf, index: u32) {
    for _ in 0..8 {
        if daemon.dns_registry_map[&index].probing.is_empty() {
            return;
        }
        for probe in daemon
            .dns_registry_map
            .get_mut(&index)
            .unwrap()
            .probing
            .values_mut()
        {
            probe.next_send = Instant::now();
        }
        daemon.probing_handler();
    }
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
}

pub(super) fn unregister(daemon: &mut Zeroconf, fullname: &str) {
    let (sender, receiver) = flume::bounded(1);
    daemon.exec_command_unregister(false, registry_key(fullname), sender);
    assert!(matches!(receiver.recv().unwrap(), UnregisterStatus::OK));
}

pub(super) fn receive(daemon: &mut Zeroconf, index: u32, records: Vec<DnsRecordBox>) {
    let mut outgoing = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
    for record in records {
        outgoing.add_answer_box(record);
    }
    let intf = InterfaceId::from(&daemon.my_intfs[&index]);
    for packet in outgoing.to_data_on_wire(MAX_PKT_DEFAULT, true) {
        daemon.handle_response(DnsIncoming::new(packet, intf.clone()).unwrap(), index);
    }
}

fn run_registration_resend(daemon: &mut Zeroconf, fullname: &str, index: u32) {
    let key = registry_key(fullname);
    daemon.retransmissions.retain(|rerun| match &rerun.command {
        Command::RegisterResend(name, current) => *current != index || registry_key(name) != key,
        _ => true,
    });
    daemon.exec_command_register_resend(key, index).unwrap();
}

fn registration_resends(daemon: &Zeroconf, fullname: &str, index: u32) -> usize {
    daemon
        .retransmissions
        .iter()
        .filter(|rerun| match &rerun.command {
            Command::RegisterResend(name, current) => {
                *current == index && registry_key(name) == registry_key(fullname)
            }
            _ => false,
        })
        .count()
}

fn expire_multicast_window(daemon: &mut Zeroconf, index: u32) {
    let registry = daemon.dns_registry_map.get_mut(&index).unwrap();
    for sent in registry
        .last_multicast_v4
        .values_mut()
        .chain(registry.last_multicast_v6.values_mut())
    {
        *sent = Instant::now() - Duration::from_secs(2);
    }
}

fn record<T: 'static>(records: &[DnsRecordBox]) -> &T {
    records
        .iter()
        .find_map(|record| record.any().downcast_ref::<T>())
        .expect("published record has the expected type")
}

fn active_count(daemon: &Zeroconf) -> usize {
    daemon
        .dns_registry_map
        .values()
        .map(|registry| registry.unique_records().count())
        .sum()
}

#[test]
fn distinct_registrations_release_all_owned_records() {
    let (mut daemon, index) = daemon();
    for version in 0..1000 {
        let service = service(
            &format!("instance-{version}"),
            "shared.local.",
            "127.0.0.1",
            "A",
        );
        let fullname = service.get_fullname().to_string();
        daemon.register_service(service);
        finish(&mut daemon, index);
        assert_eq!(active_count(&daemon), 3);
        unregister(&mut daemon, &fullname);
        assert!(daemon.my_services.is_empty());
        assert_eq!(active_count(&daemon), 0);
        assert!(daemon.dns_registry_map[&index].probing.is_empty());
        assert!(daemon.dns_registry_map[&index].name_changes.is_empty());
        assert!(daemon.retransmissions.len() <= 2);
        // Complete this lifecycle's optional goodbye retries before the next one.
        // The fixture drives callbacks directly instead of waiting on wall time.
        for retry in std::mem::take(&mut daemon.retransmissions) {
            assert!(matches!(&retry.command, Command::UnregisterResend(..)));
            daemon.exec_command(retry.command, true);
        }
    }
}

#[test]
fn txt_and_port_updates_keep_established_claims_and_current_records() {
    let (mut daemon, index) = daemon();
    let original = service("updates", "updates.local.", "127.0.0.1", "0");
    let fullname = original.get_fullname().to_string();
    daemon.register_service(original);
    finish(&mut daemon, index);
    for version in 1..1001 {
        let service = ServiceInfo::new(
            "_lifecycle._tcp.local.",
            "updates",
            "updates.local.",
            "127.0.0.1",
            8080 + version,
            &[("version", version.to_string())][..],
        )
        .unwrap();
        daemon.register_service(service.clone());
        let registry = &daemon.dns_registry_map[&index];
        assert!(registry.probing.is_empty());
        assert_eq!(registry.unique_records().count(), 3);
        let records = registry.records_for_name(&fullname);
        let srv = record::<DnsSrv>(records);
        let txt = record::<DnsTxt>(records);
        assert_eq!(srv.port(), 8080 + version);
        assert_eq!(txt.text(), service.generate_txt());
        assert_eq!(
            daemon.my_services[&registry_key(&fullname)].get_status(index),
            ServiceStatus::Announced
        );
    }
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 0);
}

#[test]
fn hostname_changes_release_previous_name_claims() {
    let (mut daemon, index) = daemon();
    for version in 0..64 {
        daemon.register_service(service(
            "host-update",
            &format!("host-{version}.local."),
            "127.0.0.1",
            "A",
        ));
        finish(&mut daemon, index);
        assert_eq!(active_count(&daemon), 3);
        assert_eq!(daemon.dns_registry_map[&index].active.len(), 2);
    }
    unregister(&mut daemon, "host-update._lifecycle._tcp.local.");
    assert_eq!(active_count(&daemon), 0);
}

#[test]
fn automatic_address_changes_release_removed_addresses() {
    let (mut daemon, index) = daemon();
    let anchor = my_ip_interfaces(true)
        .into_iter()
        .find(|intf| intf.index == Some(index) && intf.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    let mut service = service("addresses", "addresses.local.", "127.0.0.1", "A").enable_addr_auto();
    service.set_interfaces(vec![IfKind::LoopbackV4]);
    let fullname = registry_key(service.get_fullname());
    daemon.register_service(service);
    finish(&mut daemon, index);
    assert_eq!(active_count(&daemon), 3);
    let mut previous: Option<Interface> = None;
    for version in 2..66 {
        if let Some(old) = previous.take() {
            daemon.del_interface_addr(&old);
            assert!(!daemon.my_intfs[&index].addrs.contains(&old.addr));
            assert!(!daemon.my_services[&fullname]
                .get_addresses()
                .contains(&old.ip()));
        }
        let alias = Interface {
            name: anchor.name.clone(),
            index: Some(index),
            oper_status: IfOperStatus::Up,
            is_p2p: false,
            addr: IfAddr::V4(Ifv4Addr {
                ip: Ipv4Addr::new(127, 0, 0, version),
                netmask: Ipv4Addr::new(255, 0, 0, 0),
                broadcast: None,
                prefixlen: 8,
            }),
            #[cfg(windows)]
            adapter_name: String::new(),
        };
        daemon.add_interface(&alias, &[anchor.clone(), alias.clone()]);
        assert_eq!(active_count(&daemon), 4);
        assert!(daemon.dns_registry_map[&index].probing.is_empty());
        previous = Some(alias);
    }
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 0);
}

#[test]
fn case_only_updates_reuse_dns_record_identity() {
    let (mut daemon, index) = daemon();
    for spelling in ["Case", "CASE", "case", "cASE"] {
        daemon.register_service(service(spelling, "case.local.", "127.0.0.1", "A"));
        finish(&mut daemon, index);
        assert_eq!(daemon.my_services.len(), 1);
        assert_eq!(active_count(&daemon), 3);
    }
}

#[test]
fn os_interface_loss_releases_registry_and_service_status() {
    let (mut daemon, index) = daemon();
    let service = service("lost", "lost.local.", "127.0.0.1", "A");
    let fullname = registry_key(service.get_fullname());
    daemon.register_service(service);
    finish(&mut daemon, index);
    daemon
        .test_down_interfaces
        .insert(daemon.my_intfs[&index].name.clone());
    daemon.check_ip_changes();
    assert!(!daemon.my_intfs.contains_key(&index));
    assert!(!daemon.dns_registry_map.contains_key(&index));
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Unknown
    );
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 0);
}

#[test]
fn pending_updates_a_b_a_complete_only_latest_proposal() {
    let (mut daemon, index) = daemon();
    let first = service("pending", "pending.local.", "127.0.0.1", "A");
    let fullname = first.get_fullname().to_string();
    daemon.register_service(first.clone());
    daemon.register_service(service("pending", "pending.local.", "127.0.0.1", "B"));
    daemon.register_service(first.clone());
    assert_eq!(
        daemon.dns_registry_map[&index].probing[&registry_key(&fullname)]
            .records
            .len(),
        2
    );
    finish(&mut daemon, index);
    assert_eq!(active_count(&daemon), 3);
    let txt = record::<DnsTxt>(daemon.dns_registry_map[&index].records_for_name(&fullname));
    assert_eq!(txt.text(), first.generate_txt());
    daemon.register_service(first);
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
}

#[test]
fn established_updates_a_b_a_never_create_obsolete_probes() {
    let (mut daemon, index) = daemon();
    let first = service("revert", "revert.local.", "127.0.0.1", "A");
    let fullname = first.get_fullname().to_string();
    daemon.register_service(first.clone());
    finish(&mut daemon, index);
    daemon.register_service(service("revert", "revert.local.", "127.0.0.1", "B"));
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    daemon.register_service(first.clone());
    daemon.probing_handler();
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    let txt = record::<DnsTxt>(daemon.dns_registry_map[&index].records_for_name(&fullname));
    assert_eq!(txt.text(), first.generate_txt());
    assert_eq!(active_count(&daemon), 3);
}

#[test]
fn unregister_cancels_initial_pending_claims_without_goodbyes() {
    let (mut daemon, index) = daemon();
    let published = service("pending-remove", "pending-remove.local.", "127.0.0.1", "A");
    let fullname = published.get_fullname().to_string();
    daemon.register_service(published);
    assert!(!daemon.dns_registry_map[&index].probing.is_empty());
    unregister(&mut daemon, &fullname);
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    assert_eq!(active_count(&daemon), 0);
    assert!(daemon.retransmissions.is_empty());
}

#[test]
fn conflict_renames_are_current_and_disappear_on_unregister() {
    let (mut daemon, index) = daemon();
    for cycle in 0..16 {
        let published = service(
            &format!("conflict-{cycle}"),
            "host.local.",
            "127.0.0.1",
            "A",
        );
        let fullname = published.get_fullname().to_string();
        daemon.register_service(published);
        for probe in daemon
            .dns_registry_map
            .get_mut(&index)
            .unwrap()
            .probing
            .values_mut()
        {
            probe.next_send = Instant::now();
        }
        daemon.probing_handler();
        receive(
            &mut daemon,
            index,
            vec![DnsTxt::new(&fullname, CLASS_IN, 120, b"\x09version=B".to_vec()).boxed()],
        );
        assert_ne!(
            daemon.dns_registry_map[&index].resolve_name(&fullname),
            fullname
        );
        finish(&mut daemon, index);
        assert_eq!(active_count(&daemon), 3);
        unregister(&mut daemon, &fullname);
        assert!(daemon.dns_registry_map[&index].active.is_empty());
        assert!(daemon.dns_registry_map[&index].probing.is_empty());
        assert!(daemon.dns_registry_map[&index].name_changes.is_empty());
    }
}

#[test]
fn conflict_renaming_preserves_instance_presentation() {
    let (mut daemon, index) = daemon();
    let published = service("My Printer", "host.local.", "127.0.0.1", "A");
    let fullname = published.get_fullname().to_string();
    daemon.register_service(published);
    for probe in daemon
        .dns_registry_map
        .get_mut(&index)
        .unwrap()
        .probing
        .values_mut()
    {
        probe.next_send = Instant::now();
    }
    daemon.probing_handler();
    receive(
        &mut daemon,
        index,
        vec![DnsTxt::new(&fullname, CLASS_IN, 120, b"\x09version=B".to_vec()).boxed()],
    );
    assert_eq!(
        daemon.dns_registry_map[&index].resolve_name(&fullname),
        "My Printer (2)._lifecycle._tcp.local."
    );
}

#[test]
fn unregister_does_not_send_goodbye_for_a_shared_hostname() {
    let (mut daemon, index) = daemon();
    let first = service("first", "shared.local.", "127.0.0.1", "A");
    let fullname = first.get_fullname().to_string();
    daemon.register_service(first);
    daemon.register_service(service("second", "shared.local.", "127.0.0.1", "A"));
    finish(&mut daemon, index);
    assert_eq!(active_count(&daemon), 5);
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 3);
    let intf = InterfaceId::from(&daemon.my_intfs[&index]);
    let mut goodbyes = 0;
    for rerun in &daemon.retransmissions {
        if let Command::UnregisterResend(packet, _, _) = &rerun.command {
            let incoming = DnsIncoming::new(packet.clone(), intf.clone()).unwrap();
            goodbyes += 1;
            assert_eq!(incoming.answers().len(), 3);
            assert!(incoming
                .answers()
                .iter()
                .all(|record| record.get_record().get_ttl() == 1));
            assert!(!incoming
                .answers()
                .iter()
                .any(|record| record.get_type() == RRType::A || record.get_type() == RRType::AAAA));
        }
    }
    assert!(goodbyes > 0);
    unregister(&mut daemon, "second._lifecycle._tcp.local.");
    assert_eq!(active_count(&daemon), 0);
}

#[test]
fn shared_effective_hostname_survives_original_registration_removal() {
    let (mut daemon, index) = daemon();
    let first = service("first-renamed", "host.local.", "127.0.0.1", "A");
    let fullname = first.get_fullname().to_string();
    daemon.register_service(first);
    for probe in daemon
        .dns_registry_map
        .get_mut(&index)
        .unwrap()
        .probing
        .values_mut()
    {
        probe.next_send = Instant::now();
    }
    daemon.probing_handler();
    let intf = InterfaceId::from(&daemon.my_intfs[&index]);
    receive(
        &mut daemon,
        index,
        vec![DnsAddress::new(
            "host.local.",
            RRType::A,
            CLASS_IN,
            120,
            Ipv4Addr::new(127, 0, 0, 99).into(),
            intf,
        )
        .boxed()],
    );
    finish(&mut daemon, index);
    let effective = daemon.dns_registry_map[&index]
        .resolve_name("host.local.")
        .to_string();
    assert_ne!(effective, "host.local.");
    let second = service("second-renamed", &effective, "127.0.0.1", "A");
    let second_name = second.get_fullname().to_string();
    daemon.register_service(second.clone());
    finish(&mut daemon, index);
    assert_eq!(active_count(&daemon), 5);
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 3);
    daemon.register_service(second);
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    unregister(&mut daemon, &second_name);
    assert_eq!(active_count(&daemon), 0);
    assert!(daemon.dns_registry_map[&index].name_changes.is_empty());
}

fn goodbye_retries(daemon: &Zeroconf, index: u32) -> Vec<(Instant, Vec<u8>)> {
    daemon
        .retransmissions
        .iter()
        .filter_map(|rerun| match &rerun.command {
            Command::UnregisterResend(packet, current, _) if *current == index => {
                Some((rerun.next_time, packet.clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn unrelated_publication_changes_preserve_queued_goodbyes() {
    let (mut daemon, index) = daemon();
    let mut removed = service("removed", "removed.local.", "127.0.0.1", "A");
    removed.set_requires_probe(false);
    daemon.register_service(removed.clone());
    unregister(&mut daemon, removed.get_fullname());
    let queued = goodbye_retries(&daemon, index);
    assert_eq!(queued.len(), 1);
    let mut other = service("other", "other.local.", "127.0.0.1", "A");
    other.set_requires_probe(false);
    daemon.register_service(other.clone());
    assert_eq!(goodbye_retries(&daemon, index), queued);
    other._set_port(9090);
    daemon.register_service(other.clone());
    assert_eq!(goodbye_retries(&daemon, index), queued);
    unregister(&mut daemon, other.get_fullname());
    assert!(goodbye_retries(&daemon, index).contains(&queued[0]));
    assert_eq!(goodbye_retries(&daemon, index).len(), 2);
}

#[test]
fn reregistration_cancels_only_its_overlapping_goodbyes() {
    let (mut daemon, index) = daemon();
    let mut first = service("first-retry", "first.local.", "127.0.0.1", "A");
    first.set_requires_probe(false);
    let mut second = service("second-retry", "second.local.", "127.0.0.1", "A");
    second.set_requires_probe(false);
    daemon.register_service(first.clone());
    daemon.register_service(second.clone());
    unregister(&mut daemon, first.get_fullname());
    unregister(&mut daemon, second.get_fullname());
    let queued = goodbye_retries(&daemon, index);
    assert_eq!(queued.len(), 2);
    let interface = InterfaceId::from(&daemon.my_intfs[&index]);
    let unrelated = queued
        .iter()
        .find(|(_, packet)| {
            DnsIncoming::new(packet.clone(), interface.clone())
                .unwrap()
                .all_records()
                .any(|record| record.get_name() == second.get_fullname())
        })
        .unwrap()
        .clone();
    first._set_port(9090);
    daemon.register_service(first);
    assert_eq!(goodbye_retries(&daemon, index), vec![unrelated]);
}

#[test]
fn mixed_goodbye_packets_keep_unrelated_records_when_a_hostname_returns() {
    let (mut daemon, index) = daemon();
    let mut removed = service("old-retry", "shared-retry.local.", "127.0.0.1", "A");
    removed.set_requires_probe(false);
    daemon.register_service(removed.clone());
    unregister(&mut daemon, removed.get_fullname());
    let queued = goodbye_retries(&daemon, index);
    assert_eq!(queued.len(), 1);
    let interface = InterfaceId::from(&daemon.my_intfs[&index]);
    let records: Vec<_> = DnsIncoming::new(queued[0].1.clone(), interface.clone())
        .unwrap()
        .all_records()
        .collect();
    assert_eq!(records.len(), 4);
    let mut expected = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
    for mut record in records
        .into_iter()
        .filter(|record| record.get_type() != RRType::A)
    {
        record.get_record_mut().set_ttl(0);
        expected.add_answer_box(record);
    }
    let expected = expected.to_data_on_wire(MAX_PKT_DEFAULT, true);
    let mut replacement = service("new-retry", "shared-retry.local.", "127.0.0.2", "B");
    replacement.set_requires_probe(false);
    daemon.register_service(replacement);
    let remaining = goodbye_retries(&daemon, index);
    assert_eq!(remaining, vec![(queued[0].0, expected[0].clone())]);
    let records: Vec<_> = DnsIncoming::new(remaining[0].1.clone(), interface)
        .unwrap()
        .all_records()
        .collect();
    assert_eq!(records.len(), 3);
    assert!(records
        .iter()
        .any(|record| record.get_type() == RRType::PTR));
    assert!(records
        .iter()
        .any(|record| record.get_type() == RRType::SRV));
    assert!(records
        .iter()
        .any(|record| record.get_type() == RRType::TXT));
}

#[test]
fn rate_limited_first_announcement_waits_for_actual_send_and_retries_once() {
    let (mut daemon, index) = daemon();
    let mut published = service("deferred", "deferred.local.", "127.0.0.1", "A");
    published.set_requires_probe(false);
    let fullname = registry_key(published.get_fullname());
    daemon.register_service(published.clone());
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    unregister(&mut daemon, &fullname);
    let (monitor, events) = flume::bounded(16);
    daemon.monitors.push(monitor);
    daemon.register_service(published);
    assert_ne!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert!(events.try_recv().is_err());
    assert_eq!(registration_resends(&daemon, &fullname, index), 1);

    run_registration_resend(&mut daemon, &fullname, index);
    assert_ne!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert!(events.try_recv().is_err());
    assert_eq!(registration_resends(&daemon, &fullname, index), 1);

    expire_multicast_window(&mut daemon, index);
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert!(matches!(
        events.try_recv().unwrap(),
        DaemonEvent::Announce(..)
    ));
    assert_eq!(registration_resends(&daemon, &fullname, index), 1);

    expire_multicast_window(&mut daemon, index);
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(registration_resends(&daemon, &fullname, index), 0);
}

#[test]
fn partially_rate_limited_resend_keeps_latest_data_pending() {
    let (mut daemon, index) = daemon();
    let mut published = service("partial", "partial.local.", "127.0.0.1", "A");
    published.set_requires_probe(false);
    let fullname = registry_key(published.get_fullname());
    daemon.register_service(published);
    expire_multicast_window(&mut daemon, index);
    let mut updated = service("partial", "partial.local.", "127.0.0.1", "B");
    updated.set_requires_probe(false);
    daemon.register_service(updated.clone());
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(registration_resends(&daemon, &fullname, index), 1);
    expire_multicast_window(&mut daemon, index);
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(registration_resends(&daemon, &fullname, index), 0);
    let txt = record::<DnsTxt>(daemon.dns_registry_map[&index].records_for_name(&fullname));
    assert_eq!(txt.text(), updated.generate_txt());
}

#[test]
fn unavailable_transports_do_not_create_publication_retry_loops() {
    let (mut daemon, index) = daemon();
    let mut published = service("unavailable", "unavailable.local.", "127.0.0.1", "A");
    published.set_requires_probe(false);
    let fullname = published.get_fullname().to_string();
    daemon.register_service(published);
    daemon.ipv4_sock = None;
    daemon.ipv6_sock = None;
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(registration_resends(&daemon, &fullname, index), 0);
}

#[test]
fn any_probe_defers_to_another_record_type_at_the_hostname() {
    let (mut daemon, index) = daemon();
    let published = service("foreign-type", "role.local.", "127.0.0.1", "A");
    let fullname = published.get_fullname().to_string();
    daemon.register_service(published);
    for probe in daemon
        .dns_registry_map
        .get_mut(&index)
        .unwrap()
        .probing
        .values_mut()
    {
        probe.next_send = Instant::now();
    }
    daemon.probing_handler();
    receive(
        &mut daemon,
        index,
        vec![DnsTxt::new("role.local.", CLASS_IN, 120, b"\x03x=y".to_vec()).boxed()],
    );
    assert_eq!(
        daemon.dns_registry_map[&index].resolve_name("role.local."),
        "role-2.local."
    );
    finish(&mut daemon, index);
    assert_eq!(active_count(&daemon), 3);
    assert!(!daemon.dns_registry_map[&index]
        .active
        .contains_key("role.local."));
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 0);
}

#[test]
fn a_looped_back_old_srv_does_not_conflict_with_the_updated_registration() {
    let (mut daemon, index) = daemon();
    let published = service("echo", "old.local.", "127.0.0.1", "A");
    let fullname = published.get_fullname().to_string();
    daemon.register_service(published);
    finish(&mut daemon, index);
    let old_srv = daemon.dns_registry_map[&index]
        .records_for_name(&fullname)
        .iter()
        .find(|record| record.get_type() == RRType::SRV)
        .unwrap()
        .clone();
    assert!(daemon.dns_registry_map[&index].was_recently_multicast(&old_srv, Instant::now()));

    daemon.register_service(service("echo", "new.local.", "127.0.0.1", "A"));
    // Both multicast groups can deliver the previous response after the update.
    receive(&mut daemon, index, vec![old_srv.clone()]);
    receive(&mut daemon, index, vec![old_srv]);
    finish(&mut daemon, index);
    let registry = &daemon.dns_registry_map[&index];
    assert_eq!(registry.resolve_name(&fullname), fullname);
    assert!(registry.name_changes.is_empty());
    assert_eq!(active_count(&daemon), 3);
    assert!(registry.records_for_name("old.local.").is_empty());
    let current_srv = record::<DnsSrv>(registry.records_for_name(&fullname));
    assert_eq!(current_srv.host(), "new.local.");
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 0);
}

fn published_srv_host(daemon: &Zeroconf, index: u32, fullname: &str) -> String {
    record::<DnsSrv>(daemon.dns_registry_map[&index].records_for_name(fullname))
        .host()
        .to_string()
}

#[test]
fn hostname_updates_keep_the_old_publication_until_the_new_host_is_claimed() {
    let (mut daemon, index) = daemon();
    let original = service("staged", "old.local.", "127.0.0.1", "A");
    let fullname = registry_key(original.get_fullname());
    daemon.register_service(original);
    finish(&mut daemon, index);
    let before = daemon.publication_snapshot();
    daemon.register_service(service("staged", "new.local.", "127.0.0.1", "B"));
    assert_eq!(daemon.my_services[&fullname].get_hostname(), "old.local.");
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert_eq!(published_srv_host(&daemon, index, &fullname), "old.local.");
    assert_eq!(daemon.pending_registrations.len(), 1);
    assert_eq!(
        before[&index].len(),
        daemon.publication_snapshot()[&index].len()
    );
    assert!(!daemon
        .retransmissions
        .iter()
        .any(|rerun| matches!(rerun.command, Command::UnregisterResend(..))));
    finish(&mut daemon, index);
    assert!(daemon.pending_registrations.is_empty());
    assert_eq!(daemon.my_services[&fullname].get_hostname(), "new.local.");
    assert_eq!(published_srv_host(&daemon, index, &fullname), "new.local.");
    assert_eq!(active_count(&daemon), 3);
    for rerun in &daemon.retransmissions {
        if let Command::UnregisterResend(packet, _, _) = &rerun.command {
            let message =
                DnsIncoming::new(packet.clone(), (&daemon.my_intfs[&index]).into()).unwrap();
            assert!(!message.all_records().any(|record| matches!(
                record.get_type(),
                RRType::PTR | RRType::SRV | RRType::TXT
            )));
        }
    }
}

#[test]
fn rapid_pending_hostname_changes_keep_only_the_latest_request() {
    let (mut daemon, index) = daemon();
    let original = service("latest-host", "a.local.", "127.0.0.1", "A");
    let fullname = registry_key(original.get_fullname());
    daemon.register_service(original);
    finish(&mut daemon, index);
    for hostname in ["b.local.", "c.local."] {
        daemon.register_service(service("latest-host", hostname, "127.0.0.1", "B"));
        assert_eq!(daemon.pending_registrations.len(), 1);
        assert_eq!(
            daemon.pending_registrations[&fullname].get_hostname(),
            hostname
        );
        assert_eq!(published_srv_host(&daemon, index, &fullname), "a.local.");
        assert_eq!(daemon.dns_registry_map[&index].probing.len(), 1);
    }
    daemon.register_service(service("latest-host", "a.local.", "127.0.0.1", "C"));
    assert!(daemon.pending_registrations.is_empty());
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    assert_eq!(active_count(&daemon), 3);
    daemon.register_service(service("latest-host", "d.local.", "127.0.0.1", "D"));
    unregister(&mut daemon, &fullname);
    assert!(daemon.pending_registrations.is_empty());
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    assert_eq!(active_count(&daemon), 0);
    daemon.probing_handler();
    assert!(daemon.my_services.is_empty());
}

#[test]
fn conflicts_on_a_pending_hostname_keep_the_current_service_announced() {
    let (mut daemon, index) = daemon();
    let original = service("pending-conflict", "old.local.", "127.0.0.1", "A");
    let fullname = registry_key(original.get_fullname());
    daemon.register_service(original);
    finish(&mut daemon, index);
    daemon.register_service(service("pending-conflict", "new.local.", "127.0.0.1", "B"));
    for probe in daemon
        .dns_registry_map
        .get_mut(&index)
        .unwrap()
        .probing
        .values_mut()
    {
        probe.next_send = Instant::now();
    }
    daemon.probing_handler();
    let intf = InterfaceId::from(&daemon.my_intfs[&index]);
    receive(
        &mut daemon,
        index,
        vec![DnsAddress::new(
            "new.local.",
            RRType::A,
            CLASS_IN,
            120,
            Ipv4Addr::new(127, 0, 0, 99).into(),
            intf,
        )
        .boxed()],
    );
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert_eq!(published_srv_host(&daemon, index, &fullname), "old.local.");
    assert_eq!(
        daemon.dns_registry_map[&index].resolve_name("new.local."),
        "new-2.local."
    );
    finish(&mut daemon, index);
    assert_eq!(
        published_srv_host(&daemon, index, &fullname),
        "new-2.local."
    );
    assert_eq!(active_count(&daemon), 3);
    unregister(&mut daemon, &fullname);
    assert!(daemon.dns_registry_map[&index].name_changes.is_empty());
}

#[test]
fn recent_own_records_do_not_hide_a_different_srv_conflict() {
    let (mut daemon, index) = daemon();
    let published = service("genuine", "genuine.local.", "127.0.0.1", "A");
    let fullname = published.get_fullname().to_string();
    daemon.register_service(published);
    finish(&mut daemon, index);
    let foreign = DnsSrv::new(
        &fullname,
        CLASS_IN,
        120,
        0,
        0,
        9999,
        "foreign.local.".to_string(),
    )
    .boxed();
    assert!(!daemon.dns_registry_map[&index].was_recently_multicast(&foreign, Instant::now()));
    receive(&mut daemon, index, vec![foreign]);
    assert!(!daemon.dns_registry_map[&index].is_claimed(&fullname));
    assert!(daemon.dns_registry_map[&index]
        .probing
        .contains_key(&registry_key(&fullname)));
}

#[test]
fn unavailable_sockets_do_not_complete_a_probe() {
    let (mut daemon, index) = daemon();
    daemon.ipv4_sock = None;
    daemon.ipv6_sock = None;
    daemon.register_service(service("unsent", "unsent.local.", "127.0.0.1", "A"));
    for _ in 0..8 {
        for probe in daemon
            .dns_registry_map
            .get_mut(&index)
            .unwrap()
            .probing
            .values_mut()
        {
            probe.next_send = Instant::now();
        }
        daemon.probing_handler();
    }
    let registry = &daemon.dns_registry_map[&index];
    assert!(registry.active.is_empty());
    assert!(registry
        .probing
        .values()
        .all(|probe| probe.probes_sent == 0));
    assert_eq!(
        daemon
            .my_services
            .values()
            .next()
            .unwrap()
            .get_status(index),
        ServiceStatus::Probing
    );
}

#[test]
fn failed_udp_sends_do_not_acknowledge_an_announcement() {
    let (mut daemon, index) = daemon();
    daemon.port = 0;
    let mut published = service("failed-send", "failed.local.", "127.0.0.1", "A");
    published.set_requires_probe(false);
    let fullname = registry_key(published.get_fullname());
    daemon.register_service(published);
    assert_ne!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert_eq!(
        daemon
            .retransmissions
            .iter()
            .filter(|rerun| matches!(&rerun.command, Command::RegisterResend(..)))
            .count(),
        1
    );
    daemon
        .exec_command_register_resend(fullname.clone(), index)
        .unwrap();
    assert_ne!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
}

#[test]
fn a_failed_first_announcement_recovers_through_one_current_retry() {
    let (mut daemon, index) = daemon();
    let valid_port = daemon.port;
    let published = service("recover", "recover.local.", "127.0.0.1", "A");
    let fullname = registry_key(published.get_fullname());
    daemon.register_service(published);
    for _ in 0..3 {
        for probe in daemon
            .dns_registry_map
            .get_mut(&index)
            .unwrap()
            .probing
            .values_mut()
        {
            probe.next_send = Instant::now();
        }
        daemon.probing_handler();
    }
    assert!(daemon.dns_registry_map[&index]
        .probing
        .values()
        .all(|probe| probe.probes_sent == 3));
    daemon.port = 0;
    finish(&mut daemon, index);
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Probing
    );
    assert_eq!(registration_resends(&daemon, &fullname, index), 1);
    daemon.port = valid_port;
    expire_multicast_window(&mut daemon, index);
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    assert_eq!(registration_resends(&daemon, &fullname, index), 1);
    expire_multicast_window(&mut daemon, index);
    run_registration_resend(&mut daemon, &fullname, index);
    assert_eq!(registration_resends(&daemon, &fullname, index), 0);
}

#[test]
fn unencodable_registration_does_not_create_name_claims() {
    let (mut daemon, index) = daemon();
    let (sender, events) = flume::unbounded();
    daemon.monitors.push(sender);
    let invalid_label = service(&"a".repeat(64), "valid.local.", "127.0.0.1", "A");
    daemon.register_service(invalid_label);
    let properties: Vec<_> = (0..60)
        .map(|number| (format!("key{number}"), "x".repeat(200)))
        .collect();
    let oversized = ServiceInfo::new(
        "_lifecycle._tcp.local.",
        "large",
        "valid.local.",
        "127.0.0.1",
        8080,
        properties.as_slice(),
    )
    .unwrap();
    daemon.register_service(oversized);
    assert!(daemon.my_services.is_empty());
    assert!(daemon.dns_registry_map[&index].active.is_empty());
    assert!(daemon.dns_registry_map[&index].probing.is_empty());
    assert_eq!(
        events
            .try_iter()
            .filter(|event| matches!(event, DaemonEvent::Error(..)))
            .count(),
        2
    );
}

#[test]
fn hostname_update_keeps_the_current_publication_while_probing() {
    let (mut daemon, index) = daemon();
    let original = service("transition", "old.local.", "127.0.0.1", "A");
    let fullname = registry_key(original.get_fullname());
    daemon.register_service(original);
    finish(&mut daemon, index);
    daemon.register_service(service("transition", "new.local.", "127.0.0.1", "B"));
    assert_eq!(daemon.my_services[&fullname].get_hostname(), "old.local.");
    assert_eq!(
        daemon.my_services[&fullname].get_status(index),
        ServiceStatus::Announced
    );
    let srv = record::<DnsSrv>(daemon.dns_registry_map[&index].records_for_name(&fullname));
    assert_eq!(srv.host(), "old.local.");
    finish(&mut daemon, index);
    assert_eq!(daemon.my_services[&fullname].get_hostname(), "new.local.");
    let srv = record::<DnsSrv>(daemon.dns_registry_map[&index].records_for_name(&fullname));
    assert_eq!(srv.host(), "new.local.");
    assert_eq!(active_count(&daemon), 3);
    unregister(&mut daemon, &fullname);
    assert_eq!(active_count(&daemon), 0);
}

mod publication {
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
        use super::{daemon, service, unregister};
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
