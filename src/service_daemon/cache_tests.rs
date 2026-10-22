use super::lifecycle_tests::{daemon, receive};
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
    daemon.service_queriers.insert(TY.to_string(), sender);
    receiver
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
        assert_eq!(daemon.resolved.len(), 100);
        assert_eq!(
            receiver
                .try_iter()
                .filter(|event| matches!(event, ServiceEvent::ServiceResolved(_)))
                .count(),
            100
        );
        daemon.cache.age_records(Duration::from_secs(121));
        daemon.expire_cache(Instant::now());
        assert_eq!(daemon.cache.usage(), (0, 0));
        assert!(daemon.resolved.is_empty());
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
