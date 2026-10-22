//! Received DNS records, grouped by their link and resource record set.

use crate::{
    dns_name::{CanonicalName, RrsetKey},
    dns_parser::{DnsAddress, DnsPointer, DnsRecordBox, DnsSrv, InterfaceId, RRType, CLASS_IN},
    service_info::{split_sub_domain, MyIntf},
    ScopedIp,
};
use std::{
    collections::{HashMap, HashSet},
    ops::BitOr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) struct IpType(u8);

impl IpType {
    pub const V4: Self = Self(0b01);
    pub const V6: Self = Self(0b10);

    fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for IpType {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

pub(crate) struct IntfRemovalResult {
    pub(crate) removed_instances: HashMap<String, HashSet<String>>,
    pub(crate) modified_instances: HashSet<String>,
}

pub(crate) struct CacheEviction {
    pub(crate) expired_services: HashMap<String, HashSet<String>>,
    pub(crate) expired_addrs: HashMap<String, HashSet<ScopedIp>>,
}

pub(crate) struct DnsRecordIntf {
    pub(crate) record: DnsRecordBox,
    pub(crate) src_intf: InterfaceId,
    charge: usize,
}

/// Each RRset has one owner here. Types and interfaces share the same expiry path.
pub(crate) struct DnsCache {
    records: HashMap<(u32, RrsetKey), Vec<DnsRecordIntf>>,
    max_records: usize,
    max_bytes: usize,
}

impl DnsCache {
    pub(crate) fn new() -> Self {
        Self {
            records: HashMap::new(),
            max_records: 4096,
            max_bytes: 4 * 1024 * 1024,
        }
    }

    /// Limits retained record count and charged data bytes, excluding allocator overhead.
    pub(crate) fn set_limits(&mut self, max_records: usize, max_bytes: usize) {
        self.max_records = max_records;
        self.max_bytes = max_bytes;
        loop {
            let (records, bytes) = self.usage();
            if records <= max_records && bytes <= max_bytes {
                break;
            }
            if !self.evict_oldest() {
                break;
            }
        }
    }

    pub(crate) fn usage(&self) -> (usize, usize) {
        self.records
            .values()
            .flatten()
            .fold((0, 0usize), |(count, bytes), record| {
                (count + 1, bytes.saturating_add(record.charge))
            })
    }

    fn compact(&mut self) {
        self.records.retain(|_, records| {
            if records.capacity() > records.len().saturating_mul(2) {
                records.shrink_to_fit();
            }
            !records.is_empty()
        });
        if self.records.capacity() > self.records.len().saturating_mul(2).max(8) {
            self.records.shrink_to_fit();
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let now = Instant::now();
        let oldest = self
            .records
            .iter()
            .flat_map(|(key, records)| {
                records.iter().enumerate().map(move |(index, record)| {
                    (
                        key,
                        index,
                        !record.record.get_record().is_expired(now),
                        record.record.get_created(),
                    )
                })
            })
            .min_by_key(|(_, _, live, received)| (*live, *received))
            .map(|(key, index, _, _)| (key.clone(), index));
        if let Some((key, index)) = oldest {
            if let Some(records) = self.records.get_mut(&key) {
                records.remove(index);
            }
            self.compact();
            true
        } else {
            false
        }
    }

    fn records_for(
        &self,
        name: &str,
        ty: RRType,
        index: Option<u32>,
    ) -> Option<Vec<&DnsRecordIntf>> {
        let name = CanonicalName::new(name);
        let now = Instant::now();
        let types: &[RRType] = if ty == RRType::ANY {
            &[RRType::A, RRType::AAAA]
        } else {
            std::slice::from_ref(&ty)
        };
        let mut result = Vec::new();
        if let Some(index) = index {
            for ty in types {
                let key = RrsetKey {
                    name: name.clone(),
                    rr_type: *ty,
                    class: CLASS_IN,
                };
                if let Some(records) = self.records.get(&(index, key)) {
                    result.extend(
                        records
                            .iter()
                            .filter(|record| !record.record.get_record().is_expired(now)),
                    );
                }
            }
        } else {
            for ((_, key), records) in &self.records {
                if key.name == name && key.class == CLASS_IN && types.contains(&key.rr_type) {
                    result.extend(
                        records
                            .iter()
                            .filter(|record| !record.record.get_record().is_expired(now)),
                    );
                }
            }
            result.sort_by_key(|record| record.src_intf.index);
        }
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    pub(crate) fn records_on_intf(&self, index: u32) -> Vec<&DnsRecordIntf> {
        self.records
            .iter()
            .filter(|((scope, _), _)| *scope == index)
            .flat_map(|(_, records)| records)
            .collect()
    }

    pub(crate) fn has_rrset(
        &self,
        record: &dyn crate::dns_parser::DnsRecordExt,
        index: u32,
    ) -> bool {
        self.records.contains_key(&(index, RrsetKey::new(record)))
    }

    pub(crate) fn all_ptr(&self) -> HashMap<String, Vec<&DnsRecordIntf>> {
        let mut result: HashMap<String, Vec<&DnsRecordIntf>> = HashMap::new();
        for ((_, key), records) in &self.records {
            if key.rr_type == RRType::PTR && key.class == CLASS_IN {
                result
                    .entry(key.name.as_str().to_string())
                    .or_default()
                    .extend(records);
            }
        }
        result
    }

    fn count(&self, ty: RRType) -> usize {
        self.records
            .iter()
            .filter(|((_, key), _)| key.rr_type == ty)
            .map(|(_, records)| records.len())
            .sum()
    }

    pub(crate) fn ptr_count(&self) -> usize {
        self.count(RRType::PTR)
    }
    pub(crate) fn srv_count(&self) -> usize {
        self.count(RRType::SRV)
    }
    pub(crate) fn txt_count(&self) -> usize {
        self.count(RRType::TXT)
    }
    pub(crate) fn addr_count(&self) -> usize {
        self.count(RRType::A) + self.count(RRType::AAAA)
    }
    pub(crate) fn nsec_count(&self) -> usize {
        self.count(RRType::NSEC)
    }

    pub(crate) fn get_ptr(&self, name: &str) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::PTR, None)
    }
    pub(crate) fn get_ptr_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::PTR, Some(index))
    }
    pub(crate) fn get_srv_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::SRV, Some(index))
    }
    pub(crate) fn get_txt_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::TXT, Some(index))
    }
    pub(crate) fn get_addr_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::ANY, Some(index))
    }

    pub(crate) fn subtypes(&self, fullname: &str, index: Option<u32>) -> Vec<&str> {
        let name = CanonicalName::new(fullname);
        let now = Instant::now();
        let mut subtypes: Vec<_> = self
            .records
            .iter()
            .filter(|((scope, key), _)| {
                key.rr_type == RRType::PTR
                    && key.class == CLASS_IN
                    && index.map_or(true, |index| *scope == index)
            })
            .flat_map(|((_, key), records)| {
                let (_, subtype) = split_sub_domain(key.name.as_str());
                let name = name.clone();
                records.iter().filter_map(move |record| {
                    if record.record.get_record().is_expired(now) {
                        return None;
                    }
                    record
                        .record
                        .any()
                        .downcast_ref::<DnsPointer>()
                        .filter(|ptr| CanonicalName::new(ptr.alias()) == name)
                        .and(subtype)
                })
            })
            .collect();
        subtypes.sort_unstable();
        subtypes.dedup();
        subtypes
    }

    pub(crate) fn subtype_count(&self) -> usize {
        let now = Instant::now();
        self.records
            .iter()
            .filter(|((_, key), _)| {
                key.rr_type == RRType::PTR
                    && key.class == CLASS_IN
                    && split_sub_domain(key.name.as_str()).1.is_some()
            })
            .flat_map(|(_, records)| records)
            .filter(|record| !record.record.get_record().is_expired(now))
            .filter_map(|record| record.record.any().downcast_ref::<DnsPointer>())
            .map(|ptr| CanonicalName::new(ptr.alias()))
            .collect::<HashSet<_>>()
            .len()
    }

    pub(crate) fn get_instances_on_host(&self, host: &str) -> Vec<String> {
        let host = CanonicalName::new(host);
        self.records
            .iter()
            .filter(|((_, key), _)| key.rr_type == RRType::SRV && key.class == CLASS_IN)
            .filter(|(_, records)| {
                records.iter().any(|record| {
                    record
                        .record
                        .any()
                        .downcast_ref::<DnsSrv>()
                        .map_or(false, |srv| CanonicalName::new(srv.host()) == host)
                })
            })
            .map(|((_, key), _)| key.name.as_str().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn addresses_for_host(
        &self,
        host: &str,
        index: Option<u32>,
    ) -> HashMap<String, HashSet<ScopedIp>> {
        let mut result = HashMap::new();
        for record in self
            .records_for(host, RRType::ANY, index)
            .into_iter()
            .flatten()
        {
            if let Some(addr) = record.record.any().downcast_ref::<DnsAddress>() {
                result
                    .entry(record.record.get_name().to_string())
                    .or_insert_with(HashSet::new)
                    .insert(addr.address());
            }
        }
        result
    }
    pub(crate) fn get_addresses_for_host(&self, host: &str) -> HashMap<String, HashSet<ScopedIp>> {
        self.addresses_for_host(host, None)
    }

    pub(crate) fn service_verify_queries(
        &mut self,
        instance: &str,
        expire_at: Option<Instant>,
    ) -> Vec<(String, RRType)> {
        let name = CanonicalName::new(instance);
        let mut hosts = HashSet::new();
        let mut found = false;
        for ((scope, key), records) in &mut self.records {
            if key.name != name || key.rr_type != RRType::SRV || key.class != CLASS_IN {
                continue;
            }
            found = true;
            for srv in records {
                if let Some(expire) = expire_at {
                    srv.record.set_expire_sooner(expire);
                }
                if let Some(srv) = srv.record.any().downcast_ref::<DnsSrv>() {
                    hosts.insert((*scope, CanonicalName::new(srv.host())));
                }
            }
        }
        if !found {
            return Vec::new();
        }
        let mut queries = vec![(instance.to_string(), RRType::SRV)];
        for (_, host) in &hosts {
            queries.push((host.as_str().to_string(), RRType::A));
            queries.push((host.as_str().to_string(), RRType::AAAA));
        }
        if let Some(expire) = expire_at {
            for ((scope, key), records) in &mut self.records {
                if (key.rr_type == RRType::A || key.rr_type == RRType::AAAA)
                    && hosts.contains(&(*scope, key.name.clone()))
                {
                    for record in records {
                        record.record.set_expire_sooner(expire);
                    }
                }
            }
        }
        queries
    }

    /// Admission is decided by the caller; only records in the admitted RRset are refreshed here.
    pub(crate) fn add_or_update(
        &mut self,
        intf: &MyIntf,
        incoming: DnsRecordBox,
        is_for_us: bool,
    ) -> Option<(&DnsRecordIntf, bool)> {
        match incoming.get_type() {
            RRType::PTR | RRType::SRV | RRType::TXT | RRType::A | RRType::AAAA | RRType::NSEC => {}
            _ => return None,
        }
        if !is_for_us || incoming.get_class() != CLASS_IN {
            return None;
        }
        let key = (intf.index, RrsetKey::new(incoming.as_ref()));
        let existing = self.records.get(&key).and_then(|records| {
            records
                .iter()
                .position(|record| record.record.matches(incoming.as_ref()))
        });
        if let Some(index) = existing {
            let records = self.records.get_mut(&key).unwrap();
            if incoming.get_cache_flush() {
                apply_cache_flush(records, Instant::now());
            }
            records[index].record.reset_ttl(incoming.as_ref());
            return Some((&records[index], false));
        }

        let charge = incoming.cache_charge();
        if self.max_records == 0 || charge > self.max_bytes {
            return None;
        }
        loop {
            let (count, bytes) = self.usage();
            if count < self.max_records && charge <= self.max_bytes.saturating_sub(bytes) {
                break;
            }
            if !self.evict_oldest() {
                return None;
            }
        }
        let records = self.records.entry(key).or_default();
        if incoming.get_cache_flush() {
            apply_cache_flush(records, Instant::now());
        }
        records.insert(
            0,
            DnsRecordIntf {
                record: incoming,
                src_intf: intf.into(),
                charge,
            },
        );
        Some((&records[0], true))
    }

    pub(crate) fn remove_on_intf(&mut self, record: &DnsRecordBox, index: u32) -> bool {
        let key = (index, RrsetKey::new(record.as_ref()));
        let mut removed = false;
        self.records.retain(|candidate, records| {
            if *candidate == key {
                records.retain(|existing| {
                    if existing.record.matches(record.as_ref()) {
                        removed = true;
                        false
                    } else {
                        true
                    }
                });
            }
            !records.is_empty()
        });
        self.compact();
        removed
    }

    pub(crate) fn age_records(&mut self, elapsed: Duration) {
        for record in self.records.values_mut().flatten() {
            record.record.age_by(elapsed);
        }
    }

    fn has_ptr(&self, ty: &str, instance: &str, index: Option<u32>, now: Instant) -> bool {
        let name = CanonicalName::new(instance);
        self.records_for(ty, RRType::PTR, index)
            .into_iter()
            .flatten()
            .any(|record| {
                !record.record.get_record().is_expired(now)
                    && record
                        .record
                        .any()
                        .downcast_ref::<DnsPointer>()
                        .map_or(false, |ptr| CanonicalName::new(ptr.alias()) == name)
            })
    }

    fn has_service(&self, ty: &str, instance: &str, now: Instant) -> bool {
        self.records_for(ty, RRType::PTR, None)
            .into_iter()
            .flatten()
            .any(|ptr| {
                !ptr.record.get_record().is_expired(now)
                    && ptr
                        .record
                        .any()
                        .downcast_ref::<DnsPointer>()
                        .map_or(false, |ptr| {
                            CanonicalName::new(ptr.alias()) == CanonicalName::new(instance)
                        })
                    && self
                        .get_srv_on_intf(instance, ptr.src_intf.index)
                        .into_iter()
                        .flatten()
                        .any(|srv| !srv.record.get_record().is_expired(now))
            })
    }

    /// All record types expire through this pass, independently of PTR relationships.
    pub(crate) fn evict_expired(&mut self, now: Instant) -> CacheEviction {
        let mut candidates = Vec::new();
        let mut lost_srv = HashSet::new();
        let mut expired_addrs: HashMap<String, HashSet<ScopedIp>> = HashMap::new();
        self.records.retain(|(scope, key), records| {
            records.retain(|record| {
                if !record.record.get_record().is_expired(now) {
                    return true;
                }
                match key.rr_type {
                    RRType::PTR => {
                        if let Some(ptr) = record.record.any().downcast_ref::<DnsPointer>() {
                            candidates
                                .push((key.name.as_str().to_string(), ptr.alias().to_string()));
                        }
                    }
                    RRType::SRV => {
                        lost_srv.insert((*scope, key.name.clone()));
                    }
                    RRType::A | RRType::AAAA => {
                        if let Some(addr) = record.record.any().downcast_ref::<DnsAddress>() {
                            expired_addrs
                                .entry(record.record.get_name().to_string())
                                .or_default()
                                .insert(addr.address());
                        }
                    }
                    _ => {}
                }
                false
            });
            !records.is_empty()
        });
        self.compact();
        for ((scope, key), records) in &self.records {
            if key.rr_type != RRType::PTR {
                continue;
            }
            for record in records {
                if let Some(ptr) = record.record.any().downcast_ref::<DnsPointer>() {
                    if lost_srv.contains(&(*scope, CanonicalName::new(ptr.alias()))) {
                        candidates.push((key.name.as_str().to_string(), ptr.alias().to_string()));
                    }
                }
            }
        }
        let mut expired_services: HashMap<String, HashSet<String>> = HashMap::new();
        for (ty, instance) in candidates {
            if !self.has_service(&ty, &instance, now) {
                expired_services.entry(ty).or_default().insert(instance);
            }
        }
        CacheEviction {
            expired_services,
            expired_addrs,
        }
    }

    fn refresh_interests(
        &self,
        service_types: &[&str],
        now: Instant,
    ) -> HashSet<(u32, CanonicalName, RRType)> {
        let mut names = HashSet::new();
        for ty in service_types {
            for record in self.get_ptr(ty).into_iter().flatten() {
                if record.record.get_record().is_expired(now) {
                    continue;
                }
                names.insert((record.src_intf.index, CanonicalName::new(ty), RRType::PTR));
                if let Some(ptr) = record.record.any().downcast_ref::<DnsPointer>() {
                    let instance = CanonicalName::new(ptr.alias());
                    names.insert((record.src_intf.index, instance.clone(), RRType::SRV));
                    names.insert((record.src_intf.index, instance, RRType::TXT));
                    for srv in self
                        .get_srv_on_intf(ptr.alias(), record.src_intf.index)
                        .into_iter()
                        .flatten()
                    {
                        if srv.record.get_record().is_expired(now) {
                            continue;
                        }
                        if let Some(srv) = srv.record.any().downcast_ref::<DnsSrv>() {
                            names.insert((
                                record.src_intf.index,
                                CanonicalName::new(srv.host()),
                                RRType::A,
                            ));
                            names.insert((
                                record.src_intf.index,
                                CanonicalName::new(srv.host()),
                                RRType::AAAA,
                            ));
                        }
                    }
                }
            }
        }
        names
    }

    pub(crate) fn next_deadline(
        &self,
        now: Instant,
        service_types: &[&str],
        hostnames: &[&str],
    ) -> Option<Instant> {
        let names = self.refresh_interests(service_types, now);
        let hosts: HashSet<_> = hostnames
            .iter()
            .map(|host| CanonicalName::new(host))
            .collect();
        self.records
            .iter()
            .flat_map(|((scope, key), records)| {
                let interested = key.class == CLASS_IN
                    && (names.contains(&(*scope, key.name.clone(), key.rr_type))
                        || ((key.rr_type == RRType::A || key.rr_type == RRType::AAAA)
                            && hosts.contains(&key.name)));
                records.iter().map(move |record| {
                    let expiry = record.record.get_expire();
                    if interested {
                        expiry.min(record.record.get_record().get_refresh_time())
                    } else {
                        expiry
                    }
                })
            })
            .min()
    }

    fn refresh_type(&mut self, name: &str, ty: RRType, index: Option<u32>, now: Instant) -> bool {
        let name = CanonicalName::new(name);
        self.records
            .iter_mut()
            .filter(|((scope, key), _)| {
                key.name == name
                    && key.rr_type == ty
                    && key.class == CLASS_IN
                    && index.map_or(true, |index| *scope == index)
            })
            .flat_map(|(_, records)| records)
            .fold(false, |due, record| {
                record.record.updated_refresh_time(now).is_some() || due
            })
    }

    pub(crate) fn refresh_due_ptr(&mut self, ty: &str) -> bool {
        self.refresh_type(ty, RRType::PTR, None, Instant::now())
    }

    pub(crate) fn refresh_due_srv_txt(&mut self, ty: &str) -> HashMap<String, Vec<RRType>> {
        let now = Instant::now();
        let instances: Vec<_> = self
            .get_ptr(ty)
            .into_iter()
            .flatten()
            .filter(|record| !record.record.get_record().is_expired(now))
            .filter_map(|record| {
                record
                    .record
                    .any()
                    .downcast_ref::<DnsPointer>()
                    .map(|ptr| (record.src_intf.index, ptr.alias().to_string()))
            })
            .collect();
        let mut due: HashMap<String, Vec<RRType>> = HashMap::new();
        for (scope, instance) in instances {
            for record_type in [RRType::SRV, RRType::TXT] {
                if self.refresh_type(&instance, record_type, Some(scope), now) {
                    let types = due.entry(instance.clone()).or_default();
                    if !types.contains(&record_type) {
                        types.push(record_type);
                    }
                }
            }
        }
        due
    }

    pub(crate) fn refresh_due_hosts(&mut self, ty: &str) -> HashSet<String> {
        let now = Instant::now();
        let names = self.refresh_interests(&[ty], now);
        let mut due = HashSet::new();
        for (scope, hostname, record_type) in names {
            if record_type != RRType::A && record_type != RRType::AAAA {
                continue;
            }
            if self.refresh_type(hostname.as_str(), record_type, Some(scope), now) {
                due.insert(hostname.as_str().to_string());
            }
        }
        due
    }

    pub(crate) fn refresh_due_hostname_resolutions(
        &mut self,
        hostname: &str,
    ) -> HashSet<(String, ScopedIp)> {
        let now = Instant::now();
        let name = CanonicalName::new(hostname);
        self.records
            .iter_mut()
            .filter(|((_, key), _)| {
                key.name == name
                    && key.class == CLASS_IN
                    && (key.rr_type == RRType::A || key.rr_type == RRType::AAAA)
            })
            .flat_map(|(_, records)| records)
            .filter_map(|record| {
                record.record.updated_refresh_time(now)?;
                record
                    .record
                    .any()
                    .downcast_ref::<DnsAddress>()
                    .map(|addr| (hostname.to_string(), addr.address()))
            })
            .collect()
    }

    pub(crate) fn get_known_answers_on_intf(
        &self,
        name: &str,
        ty: RRType,
        now: Instant,
        index: u32,
    ) -> Vec<&DnsRecordIntf> {
        if ty == RRType::ANY {
            return Vec::new();
        }
        self.records_for(name, ty, Some(index))
            .into_iter()
            .flatten()
            .filter(|record| {
                !record.record.get_record().is_unique()
                    && !record.record.get_record().is_expired(now)
                    && !record.record.get_record().halflife_passed(now)
            })
            .collect()
    }

    pub(crate) fn remove_addrs_on_disabled_intf(&mut self, index: u32, ip_type: IpType) {
        self.records.retain(|(scope, key), _| {
            *scope != index
                || !((key.rr_type == RRType::A && ip_type.contains(IpType::V4))
                    || (key.rr_type == RRType::AAAA && ip_type.contains(IpType::V6)))
        });
        self.compact();
    }

    pub(crate) fn remove_records_on_intf(&mut self, intf: InterfaceId) -> IntfRemovalResult {
        let mut ptrs = Vec::new();
        let mut modified_instances = HashSet::new();
        let mut hosts = HashSet::new();
        self.records.retain(|(scope, key), records| {
            if *scope != intf.index {
                return true;
            }
            match key.rr_type {
                RRType::PTR => {
                    for ptr in records {
                        if let Some(ptr) = ptr.record.any().downcast_ref::<DnsPointer>() {
                            ptrs.push((key.name.as_str().to_string(), ptr.alias().to_string()));
                        }
                    }
                }
                RRType::SRV | RRType::TXT => {
                    modified_instances.insert(key.name.as_str().to_string());
                }
                RRType::A | RRType::AAAA => {
                    hosts.insert(key.name.clone());
                }
                _ => {}
            }
            false
        });
        for host in hosts {
            modified_instances.extend(self.get_instances_on_host(host.as_str()));
        }
        let now = Instant::now();
        let mut removed_instances: HashMap<String, HashSet<String>> = HashMap::new();
        for (ty, instance) in ptrs {
            if !self.has_ptr(&ty, &instance, None, now) {
                removed_instances.entry(ty).or_default().insert(instance);
            } else {
                modified_instances.insert(instance);
            }
        }
        self.compact();
        IntfRemovalResult {
            removed_instances,
            modified_instances,
        }
    }
}

fn apply_cache_flush(records: &mut [DnsRecordIntf], now: Instant) {
    let expiry = now + Duration::from_secs(1);
    for record in records {
        if now > record.record.get_created() + Duration::from_secs(1)
            && record.record.get_expire() > expiry
        {
            record.record.set_expire(expiry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns_parser::{DnsAddress, DnsPointer, DnsRecordExt, DnsSrv, DnsTxt, RRType, CLASS_IN},
        service_info::MyIntf,
        MAX_PKT_DEFAULT,
    };
    use std::collections::HashSet;
    use std::net::IpAddr;

    fn make_intf(name: &str, index: u32) -> MyIntf {
        MyIntf {
            name: name.to_string(),
            index,
            addrs: HashSet::new(),
            max_packet_size_v4: MAX_PKT_DEFAULT,
            max_packet_size_v6: MAX_PKT_DEFAULT,
        }
    }

    /// Setup: PTR, SRV, TXT come from intf_b. ADDR exists on both intf_a and
    /// intf_b (different IPs). Removing intf_a should leave PTR/SRV/TXT intact
    /// but remove addr_a, producing a `modified_instances` entry.
    #[test]
    fn test_modified_instance_when_intf_removed() {
        let ty_domain = "_http._tcp.local.";
        let instance = "my-svc._http._tcp.local.";
        let host = "myhost.local.";
        let addr_a: IpAddr = "192.168.1.1".parse().unwrap();
        let addr_b: IpAddr = "192.168.2.1".parse().unwrap();

        let intf_a = make_intf("en0", 1);
        let intf_b = make_intf("en1", 2);

        let mut cache = DnsCache::new();

        macro_rules! add {
            ($intf:expr, $record:expr) => {
                cache.add_or_update(&$intf, $record.boxed(), true)
            };
        }

        // PTR, SRV, TXT from intf_b only — these survive when intf_a is removed.
        add!(
            intf_b,
            DnsPointer::new(ty_domain, RRType::PTR, CLASS_IN, 4500, instance.to_string())
        );
        add!(
            intf_b,
            DnsSrv::new(instance, CLASS_IN, 4500, 0, 0, 80, host.to_string())
        );
        add!(intf_b, DnsTxt::new(instance, CLASS_IN, 4500, vec![]));

        // ADDR: each interface contributes its own address (interface is part of identity).
        let intf_a_id = InterfaceId {
            name: "en0".to_string(),
            index: 1,
        };
        let intf_b_id = InterfaceId {
            name: "en1".to_string(),
            index: 2,
        };
        add!(
            intf_a,
            DnsAddress::new(host, RRType::A, CLASS_IN, 4500, addr_a, intf_a_id.clone())
        );
        add!(
            intf_b,
            DnsAddress::new(host, RRType::A, CLASS_IN, 4500, addr_b, intf_b_id)
        );

        // Remove interface A.
        let result = cache.remove_records_on_intf(intf_a_id);

        // PTR still exists via intf_b — instance is not fully removed.
        assert!(
            result.removed_instances.is_empty(),
            "expected no removed instances, got {:?}",
            result.removed_instances
        );

        // addr_a was removed, so the instance is in modified_instances.
        assert!(
            result.modified_instances.contains(instance),
            "expected {instance} in modified_instances, got {:?}",
            result.modified_instances
        );

        // Only addr_b remains in the cache.
        let addrs = cache.get_addresses_for_host(host);
        let all_ips: HashSet<IpAddr> = addrs
            .values()
            .flatten()
            .map(|scoped| scoped.to_ip_addr())
            .collect();
        assert_eq!(all_ips, HashSet::from([addr_b]));
    }

    /// A response record that is not for us (no querier) and has no existing
    /// cache entry must be dropped *without* leaving an empty `Vec` behind in
    /// the cache map. Otherwise the cache grows by one entry per distinct name
    /// seen on the network, driven by other hosts' unsolicited traffic.
    #[test]
    fn test_not_for_us_record_leaves_no_empty_entry() {
        let ty_domain = "_other._tcp.local.";
        let instance = "someone-else._other._tcp.local.";
        let host = "otherhost.local.";
        let addr: IpAddr = "192.168.1.9".parse().unwrap();

        let intf = make_intf("en0", 1);
        let intf_id = InterfaceId {
            name: "en0".to_string(),
            index: 1,
        };

        let mut cache = DnsCache::new();

        // Feed PTR / SRV / TXT / ADDR records with `is_for_us = false` and no
        // pre-existing entries. Each must be dropped.
        macro_rules! add_not_for_us {
            ($record:expr) => {{
                let result = cache.add_or_update(&intf, $record.boxed(), false);
                assert!(
                    result.is_none(),
                    "a not-for-us record should be dropped, got {:?}",
                    result.map(|(r, _)| r.record.get_name().to_string())
                );
            }};
        }

        add_not_for_us!(DnsPointer::new(
            ty_domain,
            RRType::PTR,
            CLASS_IN,
            4500,
            instance.to_string()
        ));
        add_not_for_us!(DnsSrv::new(
            instance,
            CLASS_IN,
            4500,
            0,
            0,
            80,
            host.to_string()
        ));
        add_not_for_us!(DnsTxt::new(instance, CLASS_IN, 4500, vec![]));
        add_not_for_us!(DnsAddress::new(
            host,
            RRType::A,
            CLASS_IN,
            4500,
            addr,
            intf_id
        ));

        assert!(
            cache.records.is_empty(),
            "rejected records must not allocate RRsets"
        );
    }

    /// Aging the cache by how long the system slept expires the records whose
    /// TTL ran out during the sleep, and keeps the rest with their remaining
    /// lifetime.
    #[test]
    fn test_age_records_expires_records_that_ran_out_during_sleep() {
        let ty_domain = "_http._tcp.local.";
        let instance = "my-svc._http._tcp.local.";
        let host = "myhost.local.";
        let intf = make_intf("en0", 1);

        let mut cache = DnsCache::new();

        cache.add_or_update(
            &intf,
            DnsPointer::new(ty_domain, RRType::PTR, CLASS_IN, 4500, instance.to_string()).boxed(),
            true,
        );
        cache.add_or_update(
            &intf,
            DnsSrv::new(instance, CLASS_IN, 30, 0, 0, 80, host.to_string()).boxed(),
            true,
        );
        assert!(cache
            .evict_expired(Instant::now())
            .expired_services
            .is_empty());

        let ptr = &cache.get_ptr(ty_domain).unwrap()[0].record;
        let (ptr_expire, ptr_refresh) = (ptr.get_expire(), ptr.get_record().get_refresh_time());

        // Longer than the SRV TTL, shorter than the PTR TTL.
        let slept = Duration::from_secs(60);
        cache.age_records(slept);

        let expired = cache.evict_expired(Instant::now()).expired_services;
        assert!(
            expired[ty_domain].contains(instance),
            "the SRV record ran out during the sleep"
        );

        let ptr = &cache.get_ptr(ty_domain).unwrap()[0].record;
        assert_eq!(ptr.get_expire(), ptr_expire - slept);
        assert_eq!(ptr.get_record().get_refresh_time(), ptr_refresh - slept);
    }

    #[test]
    fn orphan_records_expire_without_ptrs() {
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        for version in 0..100 {
            let instance = format!("service-{version}._http._tcp.local.");
            for record in [
                DnsSrv::new(&instance, CLASS_IN, 1, 0, 0, 80, "host.local.".to_string()).boxed(),
                DnsTxt::new(&instance, CLASS_IN, 1, vec![0]).boxed(),
                crate::dns_parser::DnsNSec::new(&instance, CLASS_IN, 1, instance.clone(), vec![0])
                    .boxed(),
            ] {
                cache.add_or_update(&intf, record, true);
            }
        }
        assert_eq!(
            (cache.srv_count(), cache.txt_count(), cache.nsec_count()),
            (100, 100, 100)
        );
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        assert!(cache.records.is_empty());
        assert!(cache.next_deadline(Instant::now(), &[], &[]).is_none());
    }

    #[test]
    fn changed_unique_records_retire_after_flush_grace() {
        use crate::dns_parser::CLASS_CACHE_FLUSH;
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        let name = "service._http._tcp.local.";
        for version in 0..100 {
            cache.age_records(Duration::from_secs(2));
            cache.add_or_update(
                &intf,
                DnsTxt::new(
                    name,
                    CLASS_IN | CLASS_CACHE_FLUSH,
                    120,
                    format!("v={version}").into_bytes(),
                )
                .boxed(),
                true,
            );
            cache.add_or_update(
                &intf,
                DnsSrv::new(
                    name,
                    CLASS_IN | CLASS_CACHE_FLUSH,
                    120,
                    0,
                    0,
                    version,
                    "host.local.".to_string(),
                )
                .boxed(),
                true,
            );
            cache.evict_expired(Instant::now() + Duration::from_secs(2));
            assert_eq!((cache.txt_count(), cache.srv_count()), (1, 1));
            assert_eq!(cache.records.len(), 2);
        }
    }

    #[test]
    fn rrsets_and_flush_are_scoped_to_the_receiving_interface() {
        use crate::dns_parser::CLASS_CACHE_FLUSH;
        let intf_a = make_intf("en0", 1);
        let intf_b = make_intf("en1", 2);
        let mut cache = DnsCache::new();
        let instance = "shared._http._tcp.local.";
        for intf in [&intf_a, &intf_b] {
            for record in [
                DnsPointer::new(
                    "_http._tcp.local.",
                    RRType::PTR,
                    CLASS_IN,
                    120,
                    instance.to_string(),
                )
                .boxed(),
                DnsSrv::new(instance, CLASS_IN, 120, 0, 0, 80, "host.local.".to_string()).boxed(),
                DnsTxt::new(instance, CLASS_IN, 120, vec![0]).boxed(),
                crate::dns_parser::DnsNSec::new(
                    instance,
                    CLASS_IN,
                    120,
                    instance.to_string(),
                    vec![0],
                )
                .boxed(),
            ] {
                cache.add_or_update(intf, record, true);
            }
        }
        assert_eq!(
            (
                cache.ptr_count(),
                cache.srv_count(),
                cache.txt_count(),
                cache.nsec_count()
            ),
            (2, 2, 2, 2)
        );
        cache.age_records(Duration::from_secs(2));
        cache.add_or_update(
            &intf_a,
            DnsSrv::new(
                instance,
                CLASS_IN | CLASS_CACHE_FLUSH,
                120,
                0,
                0,
                81,
                "other.local.".to_string(),
            )
            .boxed(),
            true,
        );
        assert_eq!(cache.get_srv_on_intf(instance, 1).unwrap().len(), 2);
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        let a = cache.get_srv_on_intf(instance, 1).unwrap();
        let b = cache.get_srv_on_intf(instance, 2).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(
            a[0].record.any().downcast_ref::<DnsSrv>().unwrap().port(),
            81
        );
        assert_eq!(
            b[0].record.any().downcast_ref::<DnsSrv>().unwrap().port(),
            80
        );
        cache.remove_records_on_intf((&intf_a).into());
        assert_eq!(
            (
                cache.ptr_count(),
                cache.srv_count(),
                cache.txt_count(),
                cache.nsec_count()
            ),
            (1, 1, 1, 1)
        );
        assert!(cache.records_on_intf(1).is_empty());
    }

    fn receive_record(cache: &mut DnsCache, intf: &MyIntf, record: DnsRecordBox) {
        use crate::dns_parser::{DnsIncoming, DnsOutgoing, FLAGS_AA, FLAGS_QR_RESPONSE};
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        out.add_answer_box(record);
        for packet in out.to_data_on_wire(MAX_PKT_DEFAULT, true) {
            let message = DnsIncoming::new(packet, intf.into()).unwrap();
            for record in message.all_records() {
                cache.add_or_update(intf, record, true);
            }
        }
    }

    #[test]
    fn goodbye_and_rescue_apply_to_one_link() {
        let a = make_intf("en0", 1);
        let b = make_intf("en1", 2);
        let mut cache = DnsCache::new();
        let instance = "service._http._tcp.local.";
        for intf in [&a, &b] {
            receive_record(
                &mut cache,
                intf,
                DnsSrv::new(instance, CLASS_IN, 120, 0, 0, 80, "host.local.".to_string()).boxed(),
            );
        }
        receive_record(
            &mut cache,
            &a,
            DnsSrv::new(instance, CLASS_IN, 0, 0, 0, 80, "host.local.".to_string()).boxed(),
        );
        assert_eq!(cache.srv_count(), 2);
        let future = Instant::now() + Duration::from_secs(2);
        assert!(
            cache.get_srv_on_intf(instance, 1).unwrap()[0]
                .record
                .get_expire()
                < future
        );
        assert!(
            cache.get_srv_on_intf(instance, 2).unwrap()[0]
                .record
                .get_expire()
                > future
        );
        receive_record(
            &mut cache,
            &a,
            DnsSrv::new(instance, CLASS_IN, 120, 0, 0, 80, "host.local.".to_string()).boxed(),
        );
        cache.evict_expired(future);
        assert_eq!(cache.srv_count(), 2);
        receive_record(
            &mut cache,
            &a,
            DnsSrv::new(instance, CLASS_IN, 0, 0, 0, 80, "host.local.".to_string()).boxed(),
        );
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        assert!(cache.get_srv_on_intf(instance, 1).is_none());
        assert_eq!(cache.get_srv_on_intf(instance, 2).unwrap().len(), 1);
    }

    #[test]
    fn subtypes_follow_their_own_ptrs() {
        let intf = make_intf("en0", 1);
        let instance = "service._http._tcp.local.";
        let first = "_first._sub._http._tcp.local.";
        let second = "_second._sub._http._tcp.local.";
        let mut cache = DnsCache::new();
        for (ty, ttl) in [("_http._tcp.local.", 120), (first, 1), (second, 120)] {
            cache.add_or_update(
                &intf,
                DnsPointer::new(ty, RRType::PTR, CLASS_IN, ttl, instance.to_string()).boxed(),
                true,
            );
        }
        assert_eq!(cache.subtypes(instance, Some(1)), vec![first, second]);
        assert_eq!(cache.subtype_count(), 1);
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        assert_eq!(cache.subtypes(instance, Some(1)), vec![second]);
        let record =
            DnsPointer::new(second, RRType::PTR, CLASS_IN, 120, instance.to_string()).boxed();
        assert!(cache.remove_on_intf(&record, 1));
        assert_eq!(cache.subtype_count(), 0);
        assert_eq!(cache.ptr_count(), 1);
    }

    #[test]
    fn unrelated_records_do_not_add_refresh_wakeups() {
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        let name = "_http._tcp.local.";
        cache.add_or_update(
            &intf,
            DnsPointer::new(
                name,
                RRType::PTR,
                CLASS_IN,
                120,
                "service._http._tcp.local.".to_string(),
            )
            .boxed(),
            true,
        );
        let record = cache.get_ptr(name).unwrap()[0];
        let expiry = record.record.get_expire();
        let refresh = record.record.get_record().get_refresh_time();
        assert_eq!(cache.next_deadline(Instant::now(), &[], &[]), Some(expiry));
        assert_eq!(
            cache.next_deadline(Instant::now(), &[name], &[]),
            Some(refresh)
        );
    }

    #[test]
    fn recent_rrset_members_survive_a_flush_burst() {
        use crate::dns_parser::CLASS_CACHE_FLUSH;
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        let host = "host.local.";
        for address in ["192.168.1.1", "192.168.1.2"] {
            cache.add_or_update(
                &intf,
                DnsAddress::new(
                    host,
                    RRType::A,
                    CLASS_IN | CLASS_CACHE_FLUSH,
                    120,
                    address.parse().unwrap(),
                    (&intf).into(),
                )
                .boxed(),
                true,
            );
        }
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        assert_eq!(cache.addr_count(), 2);
        cache.age_records(Duration::from_secs(2));
        cache.add_or_update(
            &intf,
            DnsAddress::new(
                host,
                RRType::A,
                CLASS_IN | CLASS_CACHE_FLUSH,
                120,
                "192.168.1.1".parse().unwrap(),
                (&intf).into(),
            )
            .boxed(),
            true,
        );
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        assert_eq!(cache.addr_count(), 1);
    }

    #[test]
    fn cache_flush_metadata_is_not_record_identity_or_class() {
        use crate::dns_parser::CLASS_CACHE_FLUSH;
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        let instance = "Service._http._tcp.local.";
        for class in [CLASS_IN, CLASS_IN | CLASS_CACHE_FLUSH] {
            cache.add_or_update(
                &intf,
                DnsSrv::new(instance, class, 120, 0, 0, 80, "Host.local.".to_string()).boxed(),
                true,
            );
        }
        assert_eq!(cache.srv_count(), 1);
        cache.add_or_update(
            &intf,
            DnsSrv::new(instance, 3, 120, 0, 0, 80, "Host.local.".to_string()).boxed(),
            true,
        );
        assert_eq!(cache.srv_count(), 2);
        cache.age_records(Duration::from_secs(2));
        cache.add_or_update(
            &intf,
            DnsSrv::new(
                &instance.to_ascii_lowercase(),
                CLASS_IN | CLASS_CACHE_FLUSH,
                120,
                0,
                0,
                81,
                "other.local.".to_string(),
            )
            .boxed(),
            true,
        );
        cache.evict_expired(Instant::now() + Duration::from_secs(2));
        assert_eq!(cache.srv_count(), 2);
        assert_eq!(cache.get_srv_on_intf(instance, 1).unwrap().len(), 1);
        assert_eq!(
            cache.get_srv_on_intf(instance, 1).unwrap()[0]
                .record
                .any()
                .downcast_ref::<DnsSrv>()
                .unwrap()
                .port(),
            81
        );
    }

    #[test]
    fn long_lived_distinct_records_obey_cache_limits() {
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        cache.set_limits(8, 1024);
        for version in 0..100 {
            let name = format!("service-{version}._http._tcp.local.");
            cache.add_or_update(
                &intf,
                DnsTxt::new(&name, CLASS_IN, 86400, vec![0]).boxed(),
                true,
            );
            let (records, bytes) = cache.usage();
            assert!(records <= 8);
            assert!(bytes <= 1024);
        }
        assert_eq!(cache.txt_count(), 8);
        assert!(cache
            .get_txt_on_intf("service-0._http._tcp.local.", 1)
            .is_none());
        assert!(cache
            .get_txt_on_intf("service-99._http._tcp.local.", 1)
            .is_some());
        cache.set_limits(2, 1024);
        assert_eq!(cache.txt_count(), 2);
        cache.set_limits(0, 0);
        assert!(cache.records.is_empty());
    }

    #[test]
    fn oversized_records_are_rejected_without_evicting_existing_data() {
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        cache.set_limits(8, 128);
        cache.add_or_update(
            &intf,
            DnsTxt::new("small.local.", CLASS_IN, 120, vec![0]).boxed(),
            true,
        );
        let before = cache.usage();
        assert!(cache
            .add_or_update(
                &intf,
                DnsTxt::new("large.local.", CLASS_IN, 120, vec![0; 1024]).boxed(),
                true
            )
            .is_none());
        assert_eq!(cache.usage(), before);
        for _ in 0..100 {
            cache.add_or_update(
                &intf,
                DnsTxt::new("SMALL.local.", CLASS_IN, 120, vec![0]).boxed(),
                true,
            );
            assert_eq!(cache.usage(), before);
        }
    }

    #[test]
    fn unrelated_types_under_interested_names_do_not_schedule_refresh() {
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        let ty = "_http._tcp.local.";
        let instance = "service._http._tcp.local.";
        let host = "host.local.";
        for record in [
            DnsPointer::new(ty, RRType::PTR, CLASS_IN, 120, instance.to_string()).boxed(),
            DnsSrv::new(instance, CLASS_IN, 120, 0, 0, 80, host.to_string()).boxed(),
            DnsAddress::new(
                host,
                RRType::A,
                CLASS_IN,
                120,
                "192.168.1.1".parse().unwrap(),
                (&intf).into(),
            )
            .boxed(),
            DnsTxt::new(host, CLASS_IN, 10, vec![0]).boxed(),
        ] {
            cache.add_or_update(&intf, record, true);
        }
        cache.age_records(Duration::from_secs(9));
        let now = Instant::now();
        let expiry = cache.get_txt_on_intf(host, 1).unwrap()[0]
            .record
            .get_expire();
        assert!(
            cache.get_txt_on_intf(host, 1).unwrap()[0]
                .record
                .get_record()
                .get_refresh_time()
                < now
        );
        assert_eq!(cache.next_deadline(now, &[ty], &[]), Some(expiry));
        assert!(expiry > now);
    }

    #[test]
    fn capacity_prefers_expired_records_over_older_live_records() {
        let intf = make_intf("en0", 1);
        let mut cache = DnsCache::new();
        cache.set_limits(2, 1024);
        cache.add_or_update(
            &intf,
            DnsTxt::new("older.local.", CLASS_IN, 120, vec![0]).boxed(),
            true,
        );
        cache.add_or_update(
            &intf,
            DnsTxt::new("expired.local.", CLASS_IN, 1, vec![0]).boxed(),
            true,
        );
        cache.age_records(Duration::from_secs(2));
        cache.add_or_update(
            &intf,
            DnsTxt::new("new.local.", CLASS_IN, 120, vec![0]).boxed(),
            true,
        );
        assert!(cache.get_txt_on_intf("older.local.", 1).is_some());
        assert!(cache.get_txt_on_intf("new.local.", 1).is_some());
        assert_eq!(cache.usage().0, 2);
    }
}
