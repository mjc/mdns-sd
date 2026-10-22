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
        let srv = records
            .iter()
            .find_map(|record| record.any().downcast_ref::<DnsSrv>())
            .unwrap();
        let txt = records
            .iter()
            .find_map(|record| record.any().downcast_ref::<DnsTxt>())
            .unwrap();
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
    let txt = daemon.dns_registry_map[&index]
        .records_for_name(&fullname)
        .iter()
        .find_map(|record| record.any().downcast_ref::<DnsTxt>())
        .unwrap();
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
    let txt = daemon.dns_registry_map[&index]
        .records_for_name(&fullname)
        .iter()
        .find_map(|record| record.any().downcast_ref::<DnsTxt>())
        .unwrap();
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
    let txt = daemon.dns_registry_map[&index]
        .records_for_name(&fullname)
        .iter()
        .find_map(|record| record.any().downcast_ref::<DnsTxt>())
        .unwrap();
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
