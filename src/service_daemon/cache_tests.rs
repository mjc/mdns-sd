use super::*;

const TY: &str = "_cache._tcp.local.";

fn daemon() -> (Zeroconf, u32) {
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

fn service(instance: &str, hostname: &str, address: &str, txt: &str) -> ServiceInfo {
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

fn receive(daemon: &mut Zeroconf, index: u32, records: Vec<DnsRecordBox>) {
    let mut outgoing = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
    for record in records {
        outgoing.add_answer_box(record);
    }
    let intf = InterfaceId::from(&daemon.my_intfs[&index]);
    for packet in outgoing.to_data_on_wire(MAX_PKT_DEFAULT, true) {
        daemon.handle_response(DnsIncoming::new(packet, intf.clone()).unwrap(), index);
    }
}

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
fn publisher_does_not_learn_unrelated_no_ptr_responses() {
    let (mut daemon, index) = daemon();
    let mut publisher = service("publisher", "owned.local.", "127.0.0.1", "A");
    publisher.set_requires_probe(false);
    daemon.register_service(publisher);
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
}
