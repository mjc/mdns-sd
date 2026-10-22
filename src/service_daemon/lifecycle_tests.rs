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
    let (sender, receiver) = flume::unbounded();
    daemon.monitors.push(sender);
    expire_multicast_window(&mut daemon, index);
    let current = daemon.my_services[&registry_key(&fullname)].clone();
    daemon.register_service(current);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, DaemonEvent::Announce(..))));
    assert_eq!(active_count(&daemon), 3);
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
    unregister(&mut daemon, "case._lifecycle._tcp.local.");
    let (sender, commands) = flume::unbounded();
    let handle = ServiceDaemon {
        sender,
        waker: daemon.waker.clone(),
    };
    let published = service("École", "school.local.", "127.0.0.1", "A");
    let fullname = published.get_fullname().to_string();
    handle.register(published).unwrap();
    daemon.exec_command(commands.recv().unwrap(), false);
    finish(&mut daemon, index);
    let result = handle.unregister(&fullname).unwrap();
    daemon.exec_command(commands.recv().unwrap(), false);
    assert!(matches!(result.recv().unwrap(), UnregisterStatus::OK));
    assert_eq!(active_count(&daemon), 0);
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
