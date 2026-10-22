use super::lifecycle_tests::{daemon, finish, receive, service};
use super::*;

const TY: &str = "_cache._tcp.local.";

fn discovery_records(
    daemon: &Zeroconf,
    index: u32,
    instance: &str,
    host: &str,
    ttl: u32,
    include_ptr: bool,
) -> Vec<DnsRecordBox> {
    let mut records = Vec::new();
    if include_ptr {
        records.push(DnsPointer::new(TY, RRType::PTR, CLASS_IN, ttl, instance.to_string()).boxed());
    }
    records.extend([
        DnsSrv::new(
            instance,
            CLASS_IN | CLASS_CACHE_FLUSH,
            ttl,
            0,
            0,
            8080,
            host.to_string(),
        )
        .boxed(),
        DnsTxt::new(
            instance,
            CLASS_IN | CLASS_CACHE_FLUSH,
            ttl,
            b"\x03v=A".to_vec(),
        )
        .boxed(),
        DnsAddress::new(
            host,
            RRType::A,
            CLASS_IN | CLASS_CACHE_FLUSH,
            ttl,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            (&daemon.my_intfs[&index]).into(),
        )
        .boxed(),
    ]);
    records
}

fn subscribe(daemon: &mut Zeroconf) -> Receiver<ServiceEvent> {
    let (sender, receiver) = flume::unbounded();
    daemon
        .service_queriers
        .insert(TY.to_string(), sender.into());
    receiver
}

fn second_interface(daemon: &mut Zeroconf, index: u32) -> u32 {
    let other = index + 65_536;
    let first = &daemon.my_intfs[&index];
    daemon.my_intfs.insert(
        other,
        MyIntf {
            name: "cache-test-link".to_string(),
            index: other,
            addrs: first.addrs.clone(),
            max_packet_size_v4: first.max_packet_size_v4,
            max_packet_size_v6: first.max_packet_size_v6,
        },
    );
    other
}

fn found_count(events: &[ServiceEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, ServiceEvent::ServiceFound(..)))
        .count()
}

#[test]
fn publisher_does_not_learn_unrelated_no_ptr_responses() {
    let (mut daemon, index) = daemon();
    daemon.register_service(service("publisher", "owned.local.", "127.0.0.1", "A"));
    finish(&mut daemon, index);
    assert!(daemon.service_queriers.is_empty());
    assert!(daemon.hostname_resolvers.is_empty());
    assert!(!daemon.accept_unsolicited);
    let deadlines = daemon.scheduled_deadlines();
    for version in 0..100 {
        let instance = format!("foreign-{version}.{TY}");
        let host = format!("foreign-{version}.local.");
        let mut records = discovery_records(&daemon, index, &instance, &host, 86400, false);
        records.push(DnsNSec::new(&instance, CLASS_IN, 86400, instance.clone(), vec![0]).boxed());
        receive(&mut daemon, index, records);
        assert_eq!(daemon.cache.usage(), (0, 0));
        assert_eq!(daemon.scheduled_deadlines(), deadlines);
    }
    assert_eq!(daemon.my_services.len(), 1);
    assert_eq!(
        daemon.dns_registry_map[&index]
            .active
            .values()
            .map(Vec::len)
            .sum::<usize>(),
        3
    );
}

#[test]
fn repeated_ptr_refreshes_keep_one_record_and_one_live_deadline() {
    let (mut daemon, index) = daemon();
    daemon.accept_unsolicited = true;
    let baseline = daemon.scheduled_deadlines();
    for _ in 0..10_000 {
        receive(
            &mut daemon,
            index,
            vec![DnsPointer::new(TY, RRType::PTR, CLASS_IN, 4500, format!("fixed.{TY}")).boxed()],
        );
        assert_eq!(daemon.cache.ptr_count(), 1);
        assert_eq!(daemon.cache.usage().0, 1);
        assert_eq!(daemon.scheduled_deadlines(), baseline + 1);
    }
}

#[test]
fn parsed_orphan_records_expire_without_discovery_subscriptions() {
    let (mut daemon, index) = daemon();
    daemon.accept_unsolicited = true;
    let baseline = daemon.scheduled_deadlines();
    for version in 0..100 {
        let instance = format!("orphan-{version}.{TY}");
        let host = format!("orphan-{version}.local.");
        let mut records = discovery_records(&daemon, index, &instance, &host, 120, false);
        records.push(DnsNSec::new(&instance, CLASS_IN, 120, instance.clone(), vec![0]).boxed());
        receive(&mut daemon, index, records);
    }
    assert_eq!(
        (
            daemon.cache.ptr_count(),
            daemon.cache.srv_count(),
            daemon.cache.txt_count(),
            daemon.cache.nsec_count(),
            daemon.cache.addr_count()
        ),
        (0, 100, 100, 100, 100)
    );
    daemon.cache.age_records(Duration::from_secs(121));
    daemon.cache.evict_expired(Instant::now());
    assert_eq!(daemon.cache.usage(), (0, 0));
    assert_eq!(daemon.scheduled_deadlines(), baseline);
}

#[test]
fn verification_without_browsing_accepts_changed_target_and_new_address() {
    let (mut daemon, index) = daemon();
    let instance = format!("verify.{TY}");
    daemon.accept_unsolicited = true;
    let records = discovery_records(&daemon, index, &instance, "old.local.", 120, false);
    receive(&mut daemon, index, records);
    daemon.accept_unsolicited = false;
    assert!(daemon.service_queriers.is_empty());
    assert!(daemon.hostname_resolvers.is_empty());
    daemon.exec_command_verify(instance.clone(), Duration::from_secs(10), false);
    let deadline = daemon.verifications[&instance];
    assert!(
        daemon.cache.get_srv_on_intf(&instance, index).unwrap()[0]
            .record
            .get_expire()
            <= deadline
    );
    let records = discovery_records(&daemon, index, &instance, "new.local.", 120, false);
    receive(&mut daemon, index, records);
    let records = daemon.cache.get_srv_on_intf(&instance, index).unwrap();
    let updated = records
        .iter()
        .find(|record| {
            record
                .record
                .any()
                .downcast_ref::<DnsSrv>()
                .is_some_and(|srv| srv.host() == "new.local.")
        })
        .unwrap();
    assert!(updated.record.get_expire() > deadline);
    assert_eq!(
        daemon
            .cache
            .get_addr_on_intf("new.local.", index)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn other_dns_classes_cannot_create_in_class_discovery_dependencies() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    let instance = format!("foreign-class.{TY}");
    let mut records = discovery_records(&daemon, index, &instance, "foreign.local.", 120, false);
    records.insert(
        0,
        DnsPointer::new(TY, RRType::PTR, 3, 120, instance).boxed(),
    );
    receive(&mut daemon, index, records);
    assert_eq!(daemon.cache.usage(), (0, 0));
    assert!(receiver.is_empty());
    assert!(daemon.pending_resolves.is_empty());
}

#[test]
fn capacity_eviction_inside_a_packet_does_not_emit_phantom_found_events() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    daemon.cache.set_limits(1, 1024 * 1024);
    let records = discovery_records(
        &daemon,
        index,
        &format!("capacity.{TY}"),
        "capacity.local.",
        120,
        true,
    );
    receive(&mut daemon, index, records);
    assert_eq!(daemon.cache.usage().0, 1);
    assert!(receiver.is_empty());
    assert!(daemon.service_queriers[TY].delivered.is_empty());
    assert!(daemon.pending_resolves.is_empty());
}

#[test]
fn lowering_cache_limits_retires_delivery_and_hostname_state_once() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    let (sender, host_receiver) = flume::unbounded();
    daemon
        .hostname_resolvers
        .insert("capacity.local.".to_string(), (sender, None));
    let records = discovery_records(
        &daemon,
        index,
        &format!("capacity.{TY}"),
        "capacity.local.",
        120,
        true,
    );
    receive(&mut daemon, index, records);
    assert_eq!(daemon.service_queriers[TY].delivered.len(), 1);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(_))));
    assert!(host_receiver
        .try_iter()
        .any(|event| matches!(event, HostnameResolutionEvent::AddressesFound(_, _))));
    daemon.process_set_option(DaemonOption::CacheLimits(0, 0));
    assert_eq!(daemon.cache.usage(), (0, 0));
    assert!(daemon.service_queriers[TY].delivered.is_empty());
    assert!(daemon.pending_resolves.is_empty());
    assert_eq!(
        receiver
            .try_iter()
            .filter(|event| matches!(event, ServiceEvent::ServiceRemoved(_, _)))
            .count(),
        1
    );
    assert_eq!(
        host_receiver
            .try_iter()
            .filter(|event| matches!(event, HostnameResolutionEvent::AddressesRemoved(_, _)))
            .count(),
        1
    );
    daemon.process_set_option(DaemonOption::CacheLimits(0, 0));
    assert!(receiver.is_empty());
    assert!(host_receiver.is_empty());
}

#[test]
fn resolved_batches_leave_no_delivery_or_pending_resolution_history() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    let baseline = daemon.scheduled_deadlines();
    for batch in 0..2 {
        for version in 0..100 {
            let records = discovery_records(
                &daemon,
                index,
                &format!("batch-{batch}-{version}.{TY}"),
                &format!("batch-{batch}-{version}.local."),
                120,
                true,
            );
            receive(&mut daemon, index, records);
        }
        assert_eq!(daemon.service_queriers[TY].delivered.len(), 100);
        assert_eq!(
            receiver
                .try_iter()
                .filter(|event| matches!(event, ServiceEvent::ServiceResolved(_)))
                .count(),
            100
        );
        daemon.cache.age_records(Duration::from_secs(121));
        daemon.cache.evict_expired(Instant::now());
        daemon.reconcile_browse_state();
        assert_eq!(daemon.cache.usage(), (0, 0));
        assert!(daemon.service_queriers[TY].delivered.is_empty());
        assert!(daemon.pending_resolves.is_empty());
        assert!(!daemon
            .retransmissions
            .iter()
            .any(|rerun| matches!(&rerun.command, Command::Resolve(_, _))));
        assert_eq!(
            receiver
                .try_iter()
                .filter(|event| matches!(event, ServiceEvent::ServiceRemoved(_, _)))
                .count(),
            100
        );
        assert_eq!(daemon.scheduled_deadlines(), baseline);
    }
}

#[test]
fn expired_hostname_removal_is_delivered_before_an_unrelated_response() {
    let (mut daemon, index) = daemon();
    let host = "expired.local.";
    let (sender, receiver) = flume::unbounded();
    daemon
        .hostname_resolvers
        .insert(host.to_string(), (sender, None));
    let address = DnsAddress::new(
        host,
        RRType::A,
        CLASS_IN,
        1,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        (&daemon.my_intfs[&index]).into(),
    )
    .boxed();
    receive(&mut daemon, index, vec![address]);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, HostnameResolutionEvent::AddressesFound(_, _))));
    daemon.cache.age_records(Duration::from_secs(2));
    receive(
        &mut daemon,
        index,
        vec![DnsTxt::new("unrelated.local.", CLASS_IN, 120, vec![0]).boxed()],
    );
    assert_eq!(
        receiver
            .try_iter()
            .filter(|event| matches!(event, HostnameResolutionEvent::AddressesRemoved(_, _)))
            .count(),
        1
    );
    assert_eq!(daemon.cache.usage(), (0, 0));
}

#[test]
fn cache_only_subscription_receives_future_announcements_without_querying() {
    let (mut daemon, index) = daemon();
    daemon.next_ip_check = None;
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, TY.to_string(), 1, true, sender);
    assert!(!daemon.service_queriers[TY].querying);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::SearchStopped(_))));
    let records = discovery_records(
        &daemon,
        index,
        &format!("passive.{TY}"),
        "passive.local.",
        120,
        true,
    );
    receive(&mut daemon, index, records);
    let events: Vec<_> = receiver.try_iter().collect();
    assert_eq!(found_count(&events), 1);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, ServiceEvent::ServiceResolved(..)))
            .count(),
        1
    );
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
    assert_eq!(
        daemon.peek_earliest_timer(),
        daemon.cache.next_deadline(Instant::now(), &[], &[])
    );
}

#[test]
fn incomplete_cache_only_data_does_not_schedule_resolution_or_refresh() {
    let (mut daemon, index) = daemon();
    daemon.next_ip_check = None;
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, TY.to_string(), 1, true, sender);
    receiver.try_iter().for_each(drop);
    receive(
        &mut daemon,
        index,
        vec![DnsPointer::new(TY, RRType::PTR, CLASS_IN, 120, format!("incomplete.{TY}")).boxed()],
    );
    assert_eq!(
        receiver
            .try_iter()
            .filter(|event| matches!(event, ServiceEvent::ServiceFound(_, _)))
            .count(),
        1
    );
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
    assert_eq!(daemon.scheduled_deadlines(), 1);
    let ptr = daemon.cache.get_ptr_on_intf(TY, index).unwrap()[0];
    assert_eq!(daemon.peek_earliest_timer(), Some(ptr.record.get_expire()));
    assert!(ptr.record.get_record().get_refresh_time() < ptr.record.get_expire());
}

#[test]
fn browse_case_changes_share_one_subscription_and_stop_it() {
    let (mut daemon, index) = daemon();
    let mixed = "_CaChE._tcp.local.";
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, mixed.to_string(), 1, false, sender);
    let records = discovery_records(
        &daemon,
        index,
        &format!("Printer.{TY}"),
        "printer.local.",
        120,
        true,
    );
    receive(&mut daemon, index, records);
    let events: Vec<_> = receiver.try_iter().collect();
    assert!(events
        .iter()
        .any(|event| matches!(event, ServiceEvent::ServiceFound(..))));
    assert!(events
        .iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, TY.to_string(), 1, false, sender);
    assert_eq!(daemon.service_queriers.len(), 1);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    daemon.exec_command_stop_browse(mixed.to_string());
    assert!(daemon.service_queriers.is_empty());
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::SearchStopped(..))));
}

#[test]
fn unsolicited_unsupported_class_cannot_displace_in_records() {
    let (mut daemon, index) = daemon();
    daemon.accept_unsolicited = true;
    daemon.cache.set_limits(1, 4096);
    receive(
        &mut daemon,
        index,
        vec![DnsPointer::new(TY, RRType::PTR, CLASS_IN, 120, format!("valid.{TY}")).boxed()],
    );
    receive(
        &mut daemon,
        index,
        vec![DnsPointer::new(
            "other.local.",
            RRType::PTR,
            3,
            120,
            "unrelated.local.".to_string(),
        )
        .boxed()],
    );
    assert_eq!(daemon.cache.usage().0, 1);
    assert!(daemon.cache.get_ptr(TY).is_some());
    assert!(daemon.cache.get_ptr("other.local.").is_none());
}

#[test]
fn unresolved_link_cannot_hide_loss_of_the_last_resolved_link() {
    let (mut daemon, index) = daemon();
    let other = second_interface(&mut daemon, index);
    let receiver = subscribe(&mut daemon);
    let instance = format!("two-links.{TY}");
    receive(
        &mut daemon,
        other,
        vec![DnsPointer::new(TY, RRType::PTR, CLASS_IN, 120, instance.clone()).boxed()],
    );
    let records = discovery_records(&daemon, index, &instance, "resolved.local.", 120, true);
    receive(&mut daemon, index, records);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    daemon.cache.remove_records_on_intf(InterfaceId {
        name: daemon.my_intfs[&index].name.clone(),
        index,
    });
    daemon.reconcile_browse_state();
    assert_eq!(
        receiver
            .try_iter()
            .filter(|event| matches!(event, ServiceEvent::ServiceRemoved(..)))
            .count(),
        1
    );
    assert!(daemon.cache.get_ptr_on_intf(TY, other).is_some());
    daemon.reconcile_browse_state();
    assert!(receiver.is_empty());
}

#[test]
fn hostname_subscription_matches_normalized_backslash_presentation() {
    let (mut daemon, index) = daemon();
    let (sender, receiver) = flume::unbounded();
    let host = r"slash\q.local.";
    daemon.add_hostname_resolver(host.to_string(), sender, None);
    let address = DnsAddress::new(
        host,
        RRType::A,
        CLASS_IN,
        120,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        (&daemon.my_intfs[&index]).into(),
    )
    .boxed();
    receive(&mut daemon, index, vec![address]);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, HostnameResolutionEvent::AddressesFound(..))));
    daemon.exec_command_stop_resolve_hostname(r"slash\\q.local.".to_string());
    assert!(daemon.hostname_resolvers.is_empty());
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, HostnameResolutionEvent::SearchStopped(..))));

    let (sender, _receiver) = flume::unbounded();
    let hostname = "École.local.".to_string();
    daemon.exec_command(
        Command::ResolveHostname(hostname.clone(), 1, sender, None),
        false,
    );
    assert_eq!(daemon.hostname_resolvers.len(), 1);
    daemon.exec_command(Command::StopResolveHostname(hostname), false);
    assert!(daemon.hostname_resolvers.is_empty());
    assert!(daemon.retransmissions.is_empty());
}

#[test]
fn stopping_browses_releases_interest_without_deleting_live_records_or_verification() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    let subtype = "_color._sub._cache._tcp.local.";
    let (sender, sub_receiver) = flume::unbounded();
    daemon.exec_command_browse(false, subtype.to_string(), 1, false, sender);
    let instance = format!("shared.{TY}");
    let mut records = discovery_records(&daemon, index, &instance, "shared.local.", 120, true);
    records.push(DnsPointer::new(subtype, RRType::PTR, CLASS_IN, 120, instance.clone()).boxed());
    receive(&mut daemon, index, records);
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    assert!(sub_receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    daemon.exec_command_verify(instance.clone(), Duration::from_secs(10), false);
    let before = daemon.cache.usage();
    daemon.exec_command_stop_browse(TY.to_string());
    assert_eq!(daemon.cache.usage(), before);
    assert_eq!(daemon.service_queriers.len(), 1);
    assert!(daemon
        .resolve_service_from_cache(subtype, &instance)
        .unwrap()
        .is_valid());
    daemon.exec_command_stop_browse(subtype.to_string());
    assert!(daemon.service_queriers.is_empty());
    assert!(daemon.pending_resolves.is_empty());
    assert_eq!(daemon.cache.usage(), before);
    assert!(daemon
        .retransmissions
        .iter()
        .any(|rerun| matches!(&rerun.command, Command::Verify(name, _) if name == &instance)));
    assert!(!daemon
        .cache
        .service_verify_queries(&instance, None)
        .is_empty());
    daemon.exec_command_verify(instance, Duration::from_secs(10), true);
    daemon.cache.age_records(Duration::from_secs(121));
    daemon.expire_cache(Instant::now());
    assert_eq!(daemon.cache.usage(), (0, 0));
    assert_eq!(daemon.cache.subtype_count(), 0);
}

#[test]
fn removing_a_link_notifies_hostname_subscribers_once() {
    let (mut daemon, index) = daemon();
    let other = second_interface(&mut daemon, index);
    let host = "linked.local.";
    let (sender, receiver) = flume::unbounded();
    daemon.add_hostname_resolver(host.to_string(), sender, None);
    for scope in [index, other] {
        let address = DnsAddress::new(
            host,
            RRType::A,
            CLASS_IN,
            120,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            (&daemon.my_intfs[&scope]).into(),
        )
        .boxed();
        receive(&mut daemon, scope, vec![address]);
    }
    let _ = receiver.try_iter().collect::<Vec<_>>();
    let intf = &daemon.my_intfs[&other];
    let interfaces: Vec<_> = intf
        .addrs
        .iter()
        .map(|addr| Interface {
            name: intf.name.clone(),
            index: Some(other),
            addr: addr.clone(),
            oper_status: if_addrs::IfOperStatus::Up,
            is_p2p: false,
            #[cfg(windows)]
            adapter_name: String::new(),
        })
        .collect();
    for intf in &interfaces {
        daemon.del_interface_addr(intf);
    }
    let removed: Vec<_> = receiver
        .try_iter()
        .filter_map(|event| match event {
            HostnameResolutionEvent::AddressesRemoved(_, addresses) => Some(addresses),
            _ => None,
        })
        .collect();
    assert_eq!(removed.len(), 1);
    assert!(!removed[0].is_empty());
    assert!(daemon.cache.get_addr_on_intf(host, index).is_some());
    assert!(daemon.cache.get_addr_on_intf(host, other).is_none());
}

#[test]
fn expiry_can_resolve_a_previously_found_instance() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    let instance = format!("fallback.{TY}");
    let mut records = discovery_records(&daemon, index, &instance, "reachable.local.", 120, true);
    records.push(
        DnsSrv::new(
            &instance,
            CLASS_IN,
            1,
            0,
            0,
            9090,
            "missing.local.".to_string(),
        )
        .boxed(),
    );
    receive(&mut daemon, index, records);
    let events: Vec<_> = receiver.try_iter().collect();
    assert!(events
        .iter()
        .any(|event| matches!(event, ServiceEvent::ServiceFound(..))));
    assert!(!events
        .iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    daemon.cache.age_records(Duration::from_secs(2));
    daemon.expire_cache(Instant::now());
    let resolved: Vec<_> = receiver
        .try_iter()
        .filter_map(|event| match event {
            ServiceEvent::ServiceResolved(service) => Some(service),
            _ => None,
        })
        .collect();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].host, "reachable.local.");
    assert_eq!(resolved[0].port, 8080);
}

#[test]
fn parent_browse_retains_subtype_metadata_from_parsed_announcements() {
    let (mut daemon, index) = daemon();
    let receiver = subscribe(&mut daemon);
    let instance = format!("subtype.{TY}");
    let subtype = format!("_print._sub.{TY}");
    let mut records = discovery_records(&daemon, index, &instance, "subtype.local.", 120, true);
    records.push(DnsPointer::new(&subtype, RRType::PTR, CLASS_IN, 120, instance.clone()).boxed());
    receive(&mut daemon, index, records);
    let resolved = receiver
        .try_iter()
        .find_map(|event| match event {
            ServiceEvent::ServiceResolved(service) => Some(service),
            _ => None,
        })
        .unwrap();
    assert_eq!(resolved.sub_ty_domain.as_deref(), Some(subtype.as_str()));
    assert_eq!(
        daemon.cache.get_ptr_on_intf(&subtype, index).unwrap().len(),
        1
    );

    let (mut publisher, index) = super::lifecycle_tests::daemon();
    let mut records = discovery_records(&publisher, index, &instance, "subtype.local.", 120, true);
    records.push(DnsPointer::new(&subtype, RRType::PTR, CLASS_IN, 120, instance).boxed());
    receive(&mut publisher, index, records);
    assert_eq!(publisher.cache.usage(), (0, 0));
}

#[test]
fn type_enumeration_does_not_resolve_type_names_as_instances() {
    let (mut daemon, index) = daemon();
    let (sender, receiver) = flume::unbounded();
    daemon
        .service_queriers
        .insert(SERVICE_TYPE_ENUMERATION.to_string(), sender.into());
    let alias = "_print._sub._cache._tcp.local.";
    let mut records = discovery_records(&daemon, index, alias, "unrelated.local.", 120, false);
    records.push(
        DnsPointer::new(
            SERVICE_TYPE_ENUMERATION,
            RRType::PTR,
            CLASS_IN,
            120,
            alias.to_string(),
        )
        .boxed(),
    );
    receive(&mut daemon, index, records);
    assert_eq!(daemon.cache.ptr_count(), 1);
    assert_eq!(daemon.cache.srv_count(), 0);
    assert_eq!(daemon.cache.txt_count(), 0);
    assert_eq!(daemon.cache.addr_count(), 0);
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceFound(..))));
}

#[test]
fn cached_type_enumeration_replays_found_without_instance_resolution() {
    let (mut daemon, index) = daemon();
    daemon.accept_unsolicited = true;
    let alias = format!("misleading.{TY}");
    let mut records = discovery_records(&daemon, index, &alias, "cached.local.", 120, false);
    records
        .push(DnsPointer::new(SERVICE_TYPE_ENUMERATION, RRType::PTR, CLASS_IN, 120, alias).boxed());
    receive(&mut daemon, index, records);
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, SERVICE_TYPE_ENUMERATION.to_string(), 1, true, sender);
    let events: Vec<_> = receiver.try_iter().collect();
    assert_eq!(found_count(&events), 1);
    assert!(!events
        .iter()
        .any(|event| matches!(event, ServiceEvent::ServiceResolved(..))));
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
}

#[test]
fn an_instance_has_one_found_and_removed_lifetime_across_links() {
    for complete in [false, true] {
        let (mut daemon, first) = daemon();
        let second = second_interface(&mut daemon, first);
        let receiver = subscribe(&mut daemon);
        let instance = format!("linked.{TY}");
        for (index, name) in [
            (first, instance.clone()),
            (second, instance.to_ascii_uppercase()),
        ] {
            let records = if complete {
                discovery_records(&daemon, index, &name, "linked.local.", 120, true)
            } else {
                vec![DnsPointer::new(TY, RRType::PTR, CLASS_IN, 120, name).boxed()]
            };
            receive(&mut daemon, index, records);
        }
        let mut events: Vec<_> = receiver.try_iter().collect();
        assert_eq!(found_count(&events), 1);
        assert_eq!(daemon.cache.pointers(TY, None).count(), 2);
        assert_eq!(daemon.service_queriers[TY].delivered.len(), 1);
        let first_id = (&daemon.my_intfs[&first]).into();
        let removed = daemon.cache.remove_records_on_intf(first_id);
        daemon.reconcile_browse_state();
        daemon.resolve_updated_instances(&removed);
        let after_first: Vec<_> = receiver.try_iter().collect();
        assert!(!after_first
            .iter()
            .any(|event| matches!(event, ServiceEvent::ServiceRemoved(..))));
        assert_eq!(daemon.service_queriers[TY].delivered.len(), 1);
        assert_eq!(daemon.cache.pointers(TY, None).count(), 1);
        if complete {
            let surviving = after_first
                .iter()
                .filter_map(|event| match event {
                    ServiceEvent::ServiceResolved(service) => Some(service),
                    _ => None,
                })
                .next_back()
                .unwrap();
            assert_eq!(surviving.host, "linked.local.");
            assert_eq!(surviving.port, 8080);
            for address in &surviving.addresses {
                match address {
                    ScopedIp::V4(address) => {
                        assert!(address.interface_ids().iter().all(|id| id.index == second));
                        assert!(!address.interface_ids().is_empty());
                    }
                    ScopedIp::V6(_) => panic!("test service only has an IPv4 address"),
                }
            }
        }
        events.extend(after_first);
        let second_id = (&daemon.my_intfs[&second]).into();
        let removed = daemon.cache.remove_records_on_intf(second_id);
        daemon.reconcile_browse_state();
        daemon.resolve_updated_instances(&removed);
        events.extend(receiver.try_iter());
        assert_eq!(found_count(&events), 1);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ServiceEvent::ServiceRemoved(..)))
                .count(),
            1
        );
        assert!(daemon.service_queriers[TY].delivered.is_empty());
    }
}

#[test]
fn deduplicating_found_does_not_downgrade_a_resolved_link() {
    let (mut daemon, first) = daemon();
    let second = second_interface(&mut daemon, first);
    let receiver = subscribe(&mut daemon);
    let instance = format!("mixed.{TY}");
    let records = discovery_records(&daemon, first, &instance, "mixed.local.", 120, true);
    receive(&mut daemon, first, records);
    receive(
        &mut daemon,
        second,
        vec![DnsPointer::new(
            TY,
            RRType::PTR,
            CLASS_IN,
            120,
            instance.to_ascii_uppercase(),
        )
        .boxed()],
    );
    let key = CanonicalName::new(&instance).as_str().to_string();
    assert!(matches!(
        daemon.service_queriers[TY].delivered[&key],
        BrowseDelivery::Resolved(_)
    ));
    assert!(daemon.cache.get_srv_on_intf(&key, second).is_none());
    assert!(daemon.cache.get_ptr_on_intf(TY, second).is_some());
    assert_eq!(
        receiver
            .try_iter()
            .filter(|event| matches!(event, ServiceEvent::ServiceFound(..)))
            .count(),
        1
    );
}

#[test]
fn cached_type_enumeration_deduplicates_the_same_type_on_multiple_links() {
    let (mut daemon, first) = daemon();
    let second = second_interface(&mut daemon, first);
    daemon.accept_unsolicited = true;
    for index in [first, second] {
        receive(
            &mut daemon,
            index,
            vec![DnsPointer::new(
                SERVICE_TYPE_ENUMERATION,
                RRType::PTR,
                CLASS_IN,
                120,
                TY.to_string(),
            )
            .boxed()],
        );
    }
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, SERVICE_TYPE_ENUMERATION.to_string(), 1, true, sender);
    assert_eq!(
        receiver
            .try_iter()
            .filter(|event| matches!(event, ServiceEvent::ServiceFound(..)))
            .count(),
        1
    );
    assert_eq!(
        daemon.service_queriers[SERVICE_TYPE_ENUMERATION]
            .delivered
            .len(),
        1
    );
    assert_eq!(
        daemon
            .cache
            .pointers(SERVICE_TYPE_ENUMERATION, None)
            .count(),
        2
    );
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
}

#[test]
fn duplicate_found_retires_a_disconnected_passive_subscription() {
    let (mut daemon, first) = daemon();
    let second = second_interface(&mut daemon, first);
    let (sender, receiver) = flume::unbounded();
    daemon.exec_command_browse(false, SERVICE_TYPE_ENUMERATION.to_string(), 1, true, sender);
    receive(
        &mut daemon,
        first,
        vec![DnsPointer::new(
            SERVICE_TYPE_ENUMERATION,
            RRType::PTR,
            CLASS_IN,
            120,
            TY.to_string(),
        )
        .boxed()],
    );
    assert!(receiver
        .try_iter()
        .any(|event| matches!(event, ServiceEvent::ServiceFound(..))));
    assert_eq!(
        daemon.service_queriers[SERVICE_TYPE_ENUMERATION]
            .delivered
            .len(),
        1
    );
    drop(receiver);
    receive(
        &mut daemon,
        second,
        vec![DnsPointer::new(
            SERVICE_TYPE_ENUMERATION,
            RRType::PTR,
            CLASS_IN,
            120,
            TY.to_ascii_uppercase(),
        )
        .boxed()],
    );
    assert!(daemon.service_queriers.is_empty());
    assert!(daemon.pending_resolves.is_empty());
    assert!(daemon.retransmissions.is_empty());
}

#[test]
fn cached_complete_service_replays_once_across_links_and_alias_case() {
    for cache_only in [false, true] {
        let (mut daemon, first) = daemon();
        let second = second_interface(&mut daemon, first);
        daemon.accept_unsolicited = true;
        let instance = format!("MiXeD.{TY}");
        for (index, alias) in [
            (first, instance.clone()),
            (second, instance.to_ascii_uppercase()),
        ] {
            let records = discovery_records(&daemon, index, &alias, "startup.local.", 120, true);
            receive(&mut daemon, index, records);
        }
        assert_eq!(daemon.cache.get_ptr(TY).unwrap().len(), 2);
        let (sender, receiver) = flume::unbounded();
        daemon.exec_command_browse(false, TY.to_string(), 1, cache_only, sender);
        let events: Vec<_> = receiver.try_iter().collect();
        let found: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                ServiceEvent::ServiceFound(_, name) => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(found, vec![&instance]);
        let resolved: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                ServiceEvent::ServiceResolved(service) => Some(service),
                _ => None,
            })
            .collect();
        assert_eq!(resolved.len(), 1, "cache_only={cache_only}");
        assert_eq!(resolved[0].fullname, instance);
        assert_eq!(resolved[0].host, "startup.local.");
        assert_eq!(resolved[0].port, 8080);
        assert_eq!(resolved[0].addresses.len(), 1);
        match resolved[0].addresses.iter().next().unwrap() {
            ScopedIp::V4(address) => {
                let indices: HashSet<_> =
                    address.interface_ids().iter().map(|id| id.index).collect();
                assert_eq!(indices, HashSet::from([first, second]));
            }
            ScopedIp::V6(_) => panic!("test service only has an IPv4 address"),
        }
        assert_eq!(daemon.service_queriers[TY].delivered.len(), 1);
        assert_eq!(daemon.cache.pointers(TY, None).count(), 2);
        assert!(daemon.pending_resolves.is_empty());
    }
}
