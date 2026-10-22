//! A cache for DNS records.
//!
//! This is an internal implementation, not visible to the public API.

use crate::{
    dns_name::{CanonicalName, SERVICE_TYPE_ENUMERATION},
    dns_parser::{DnsAddress, DnsPointer, DnsRecordBox, DnsSrv, InterfaceId, RRType, CLASS_IN},
    service_info::{split_sub_domain, MyIntf},
    ScopedIp,
};
use std::{
    collections::{HashMap, HashSet},
    ops::BitOr,
    time::{Duration, Instant},
};

/// Bitflags for selecting address families.
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

/// Changes reported by the cache expiry sweep.
pub(crate) struct CacheEviction {
    /// Whether any record expired, including records without an address.
    pub(crate) changed: bool,
    pub(crate) expired_services: HashMap<String, HashSet<String>>,
    /// Expired address records grouped by hostname.
    pub(crate) expired_addrs: HashMap<String, HashSet<ScopedIp>>,
}

/// A received record, its receiving interface and retained-data charge in bytes.
pub(crate) struct DnsRecordIntf {
    pub(crate) record: DnsRecordBox,
    pub(crate) src_intf: InterfaceId,
    charge: usize,
}

/// Received RRsets share one expiry path across record types and interfaces.
pub(crate) struct DnsCache {
    /// DnsPointer records indexed by ty_domain.
    ptr: HashMap<String, Vec<DnsRecordIntf>>,
    /// DnsSrv records indexed by the fullname of an instance.
    srv: HashMap<String, Vec<DnsRecordIntf>>,
    /// DnsTxt records indexed by the fullname of an instance.
    txt: HashMap<String, Vec<DnsRecordIntf>>,
    /// Address records indexed by canonical hostname.
    addr: HashMap<String, Vec<DnsRecordIntf>>,
    /// Negative responses indexed by canonical owner name.
    nsec: HashMap<String, Vec<DnsRecordIntf>>,
    record_count: usize,
    charged_bytes: usize,
    max_records: usize,
    max_bytes: usize,
}

impl DnsCache {
    pub(crate) fn new() -> Self {
        Self {
            ptr: HashMap::new(),
            srv: HashMap::new(),
            txt: HashMap::new(),
            addr: HashMap::new(),
            nsec: HashMap::new(),
            record_count: 0,
            charged_bytes: 0,
            max_records: 4096,
            max_bytes: 4 * 1024 * 1024,
        }
    }

    fn table(&self, ty: RRType) -> Option<&HashMap<String, Vec<DnsRecordIntf>>> {
        match ty {
            RRType::PTR => Some(&self.ptr),
            RRType::SRV => Some(&self.srv),
            RRType::TXT => Some(&self.txt),
            RRType::A | RRType::AAAA | RRType::ANY => Some(&self.addr),
            RRType::NSEC => Some(&self.nsec),
            _ => None,
        }
    }

    fn table_mut(&mut self, ty: RRType) -> Option<&mut HashMap<String, Vec<DnsRecordIntf>>> {
        match ty {
            RRType::PTR => Some(&mut self.ptr),
            RRType::SRV => Some(&mut self.srv),
            RRType::TXT => Some(&mut self.txt),
            RRType::A | RRType::AAAA | RRType::ANY => Some(&mut self.addr),
            RRType::NSEC => Some(&mut self.nsec),
            _ => None,
        }
    }

    fn tables(&self) -> [&HashMap<String, Vec<DnsRecordIntf>>; 5] {
        [&self.ptr, &self.srv, &self.txt, &self.addr, &self.nsec]
    }

    fn tables_mut(&mut self) -> [&mut HashMap<String, Vec<DnsRecordIntf>>; 5] {
        [
            &mut self.ptr,
            &mut self.srv,
            &mut self.txt,
            &mut self.addr,
            &mut self.nsec,
        ]
    }

    fn records(&self) -> impl Iterator<Item = &DnsRecordIntf> {
        IntoIterator::into_iter(self.tables())
            .flat_map(|table| table.values())
            .flatten()
    }

    #[cfg(test)]
    fn rrset_count(&self) -> usize {
        self.records()
            .map(|record| {
                (
                    record.src_intf.index,
                    crate::dns_name::RrsetKey::new(record.record.as_ref()),
                )
            })
            .collect::<HashSet<_>>()
            .len()
    }

    /// Limits retained record count and charged data bytes, excluding allocator overhead.
    pub(crate) fn set_limits(&mut self, max_records: usize, max_bytes: usize) {
        self.max_records = max_records;
        self.max_bytes = max_bytes;
        self.trim_to_limits(max_records, max_bytes);
    }

    /// Returns the retained record count and charged bytes, excluding allocator overhead.
    pub(crate) fn usage(&self) -> (usize, usize) {
        (self.record_count, self.charged_bytes)
    }

    fn trim_to_limits(&mut self, max_records: usize, max_bytes: usize) -> bool {
        let mut changed = false;
        while self.record_count > max_records || self.charged_bytes > max_bytes {
            if !self.evict_oldest() {
                if changed {
                    self.compact();
                }
                return false;
            }
            changed = true;
        }
        if changed {
            self.compact();
        }
        true
    }

    fn compact(&mut self) {
        for table in self.tables_mut() {
            table.retain(|_, records| {
                if records.capacity() > records.len().saturating_mul(2) {
                    records.shrink_to_fit();
                }
                !records.is_empty()
            });
            if table.capacity() > table.len().saturating_mul(2).max(8) {
                table.shrink_to_fit();
            }
        }
    }

    fn retain_records(&mut self, mut retain: impl FnMut(&DnsRecordIntf) -> bool) {
        let mut removed_count = 0;
        let mut removed_bytes = 0;
        for table in self.tables_mut() {
            table.retain(|_, records| {
                records.retain(|record| {
                    let keep = retain(record);
                    if !keep {
                        removed_count += 1;
                        removed_bytes += record.charge;
                    }
                    keep
                });
                !records.is_empty()
            });
        }
        self.record_count -= removed_count;
        self.charged_bytes -= removed_bytes;
        self.compact();
    }

    fn evict_oldest(&mut self) -> bool {
        let now = Instant::now();
        let oldest = IntoIterator::into_iter(self.tables())
            .flat_map(|table| table.iter())
            .flat_map(|(name, records)| {
                records
                    .iter()
                    .enumerate()
                    .map(move |(index, record)| (name, index, record))
            })
            .min_by_key(|(_, _, record)| {
                (
                    !record.record.get_record().is_expired(now),
                    record.record.get_created(),
                )
            })
            .map(|(name, index, record)| (record.record.get_type(), name.clone(), index));
        let Some((ty, name, index)) = oldest else {
            return false;
        };
        let record = self
            .table_mut(ty)
            .unwrap()
            .get_mut(&name)
            .unwrap()
            .remove(index);
        self.record_count -= 1;
        self.charged_bytes -= record.charge;
        true
    }

    /// Returns unexpired IN-class records, optionally restricted to one interface.
    /// `RRType::ANY` selects A and AAAA records for address lookups.
    /// Returns `None` when no matching live records remain.
    fn records_for(
        &self,
        name: &str,
        ty: RRType,
        index: Option<u32>,
    ) -> Option<Vec<&DnsRecordIntf>> {
        let name = CanonicalName::new(name);
        let now = Instant::now();
        let mut records: Vec<_> = self
            .table(ty)?
            .get(name.as_str())?
            .iter()
            .filter(|record| {
                index.map_or(true, |index| record.src_intf.index == index)
                    && (ty == RRType::ANY || record.record.get_type() == ty)
                    && !record.record.get_record().is_expired(now)
            })
            .collect();
        if index.is_none() {
            records.sort_by_key(|record| record.src_intf.index);
        }
        (!records.is_empty()).then_some(records)
    }

    #[cfg(test)]
    pub(crate) fn records_on_intf(&self, index: u32) -> Vec<&DnsRecordIntf> {
        self.records()
            .filter(|record| record.src_intf.index == index)
            .collect()
    }

    /// Groups PTR records by service type across interfaces, including expired records.
    /// Callers must check expiry until the next cache sweep removes those records.
    pub(crate) fn all_ptr(&self) -> &HashMap<String, Vec<DnsRecordIntf>> {
        &self.ptr
    }

    /// Counts retained PTR records across interfaces.
    pub(crate) fn ptr_count(&self) -> usize {
        self.ptr.values().map(|v| v.len()).sum()
    }
    pub(crate) fn srv_count(&self) -> usize {
        self.srv.values().map(|v| v.len()).sum()
    }
    pub(crate) fn txt_count(&self) -> usize {
        self.txt.values().map(|v| v.len()).sum()
    }
    pub(crate) fn addr_count(&self) -> usize {
        self.addr.values().map(|v| v.len()).sum()
    }
    pub(crate) fn nsec_count(&self) -> usize {
        self.nsec.values().map(|v| v.len()).sum()
    }

    pub(crate) fn get_ptr(&self, ty_domain: &str) -> Option<&Vec<DnsRecordIntf>> {
        self.ptr.get(CanonicalName::new(ty_domain).as_str())
    }
    pub(crate) fn get_srv(&self, fullname: &str) -> Option<&Vec<DnsRecordIntf>> {
        self.srv.get(CanonicalName::new(fullname).as_str())
    }

    pub(crate) fn get_txt(&self, fullname: &str) -> Option<&Vec<DnsRecordIntf>> {
        self.txt.get(CanonicalName::new(fullname).as_str())
    }

    pub(crate) fn get_addr(&self, hostname: &str) -> Option<&Vec<DnsRecordIntf>> {
        self.addr.get(CanonicalName::new(hostname).as_str())
    }

    #[cfg(test)]
    pub(crate) fn get_ptr_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::PTR, Some(index))
    }

    pub(crate) fn pointers(
        &self,
        name: &str,
        index: Option<u32>,
    ) -> impl Iterator<Item = (&DnsRecordIntf, &DnsPointer)> {
        self.records_for(name, RRType::PTR, index)
            .into_iter()
            .flatten()
            .filter_map(|record| {
                record
                    .record
                    .any()
                    .downcast_ref::<DnsPointer>()
                    .map(|ptr| (record, ptr))
            })
    }

    pub(crate) fn get_srv_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::SRV, Some(index))
    }
    #[cfg(test)]
    pub(crate) fn get_txt_on_intf(&self, name: &str, index: u32) -> Option<Vec<&DnsRecordIntf>> {
        self.records_for(name, RRType::TXT, Some(index))
    }
    pub(crate) fn subtypes(&self, fullname: &str, index: Option<u32>) -> Vec<&str> {
        let name = CanonicalName::new(fullname);
        let now = Instant::now();
        let mut subtypes: Vec<_> = self
            .ptr
            .iter()
            .filter_map(|(owner, records)| {
                let (_, subtype) = split_sub_domain(owner);
                records
                    .iter()
                    .any(|record| {
                        index.map_or(true, |index| record.src_intf.index == index)
                            && !record.record.get_record().is_expired(now)
                            && record
                                .record
                                .any()
                                .downcast_ref::<DnsPointer>()
                                .is_some_and(|ptr| CanonicalName::new(ptr.alias()) == name)
                    })
                    .then_some(subtype)
                    .flatten()
            })
            .collect();
        subtypes.sort_unstable();
        subtypes.dedup();
        subtypes
    }

    pub(crate) fn subtype_count(&self) -> usize {
        let now = Instant::now();
        self.ptr
            .iter()
            .filter(|(name, _)| split_sub_domain(name).1.is_some())
            .flat_map(|(_, records)| records)
            .filter(|record| !record.record.get_record().is_expired(now))
            .filter_map(|record| record.record.any().downcast_ref::<DnsPointer>())
            .map(|ptr| CanonicalName::new(ptr.alias()))
            .collect::<HashSet<_>>()
            .len()
    }

    pub(crate) fn get_instances_on_host(&self, host: &str) -> Vec<String> {
        let host = CanonicalName::new(host);
        self.srv
            .iter()
            .filter(|(_, records)| {
                records.iter().any(|record| {
                    record
                        .record
                        .any()
                        .downcast_ref::<DnsSrv>()
                        .is_some_and(|srv| CanonicalName::new(srv.host()) == host)
                })
            })
            .map(|(instance, _)| instance.clone())
            .collect()
    }

    pub(crate) fn get_addresses_for_host(&self, host: &str) -> HashMap<String, HashSet<ScopedIp>> {
        let hostname_lower = CanonicalName::new(host);
        let mut result = HashMap::new();

        if let Some(records) = self.addr.get(hostname_lower.as_str()) {
            for record in records
                .iter()
                .filter(|record| !record.record.get_record().is_expired(Instant::now()))
            {
                if let Some(dns_addr) = record.record.any().downcast_ref::<DnsAddress>() {
                    let record_name = record.record.get_name().to_string();
                    let address = dns_addr.address();

                    // Use the entry API to insert or update the HashSet for the record_name
                    result
                        .entry(record_name)
                        .or_insert_with(HashSet::new)
                        .insert(address);
                }
            }
        }

        result
    }

    /// Returns SRV queries for an instance and address queries for its cached targets.
    /// When `expire_at` is set, shortens those records' expiry times on their links.
    pub(crate) fn service_verify_queries(
        &mut self,
        instance: &str,
        expire_at: Option<Instant>,
    ) -> Vec<(String, RRType)> {
        let Some(srv_vec) = self.srv.get_mut(CanonicalName::new(instance).as_str()) else {
            return Vec::new();
        };

        let mut query_vec = vec![(instance.to_string(), RRType::SRV)];

        for srv in srv_vec {
            if let Some(new_expire) = expire_at {
                srv.record.set_expire_sooner(new_expire);
            }

            let Some(srv_record) = srv.record.any().downcast_ref::<DnsSrv>() else {
                continue;
            };

            // Will verify addresses for the hostname.
            query_vec.push((srv_record.host().to_string(), RRType::A));
            query_vec.push((srv_record.host().to_string(), RRType::AAAA));

            if let Some(new_expire) = expire_at {
                if let Some(addrs) = self
                    .addr
                    .get_mut(CanonicalName::new(srv_record.host()).as_str())
                {
                    for addr in addrs
                        .iter_mut()
                        .filter(|addr| addr.src_intf.index == srv.src_intf.index)
                    {
                        addr.record.set_expire_sooner(new_expire);
                    }
                }
            }
        }

        query_vec
    }

    /// Refreshes existing records; admits new records only when they are for us.
    ///
    /// Returns the cached record and `true` for insertion or `false` for a TTL refresh.
    /// Returns `None` for records that are not for us, unsupported types or classes,
    /// or a new record that cannot fit within the cache limits. A refresh keeps
    /// the existing record's data charge and does not evict other records.
    pub(crate) fn add_or_update(
        &mut self,
        intf: &MyIntf,
        incoming: DnsRecordBox,
        is_for_us: bool,
    ) -> Option<(&DnsRecordIntf, bool)> {
        if incoming.get_class() != CLASS_IN {
            return None;
        }
        let ty = incoming.get_type();
        if ty == RRType::ANY {
            return None;
        }
        let name = CanonicalName::new(incoming.get_name()).as_str().to_string();
        let existing = self.table(ty)?.get(&name).and_then(|records| {
            records.iter().position(|record| {
                record.src_intf.index == intf.index && record.record.matches(incoming.as_ref())
            })
        });
        if let Some(index) = existing {
            let records = self.table_mut(ty).unwrap().get_mut(&name).unwrap();
            if incoming.get_cache_flush() {
                apply_cache_flush(&incoming, records, intf.index);
            }
            records[index].record.reset_ttl(incoming.as_ref());
            return Some((&records[index], false));
        }
        if !is_for_us {
            return None;
        }
        let charge = incoming.cache_charge();
        if self.max_records == 0 || charge > self.max_bytes {
            return None;
        }
        if !self.trim_to_limits(self.max_records - 1, self.max_bytes - charge) {
            return None;
        }
        self.record_count += 1;
        self.charged_bytes += charge;
        let records = self.table_mut(ty).unwrap().entry(name).or_default();
        if incoming.get_cache_flush() {
            apply_cache_flush(&incoming, records, intf.index);
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

    #[cfg(test)]
    pub(crate) fn remove_on_intf(&mut self, record: &DnsRecordBox, index: u32) -> bool {
        let mut removed = false;
        self.retain_records(|existing| {
            let matches =
                existing.src_intf.index == index && existing.record.matches(record.as_ref());
            removed |= matches;
            !matches
        });
        removed
    }

    pub(crate) fn remove_service_type(&mut self, ty_domain: &str) {
        let ty = CanonicalName::new(ty_domain);
        let instances: HashSet<_> = self
            .pointers(ty_domain, None)
            .map(|(_, ptr)| CanonicalName::new(ptr.alias()))
            .collect();
        let hosts: HashSet<_> = self
            .srv
            .iter()
            .filter(|(name, _)| instances.contains(&CanonicalName::new(name)))
            .flat_map(|(_, records)| records)
            .filter_map(|record| record.record.any().downcast_ref::<DnsSrv>())
            .map(|srv| CanonicalName::new(srv.host()))
            .collect();
        self.retain_records(|record| {
            let name = CanonicalName::new(record.record.get_name());
            match record.record.get_type() {
                RRType::PTR => name != ty,
                RRType::SRV | RRType::TXT => !instances.contains(&name),
                _ => true,
            }
        });
        let used_hosts: HashSet<_> = self
            .srv
            .values()
            .flatten()
            .filter_map(|record| record.record.any().downcast_ref::<DnsSrv>())
            .map(|srv| CanonicalName::new(srv.host()))
            .collect();
        self.retain_records(|record| {
            let name = CanonicalName::new(record.record.get_name());
            match record.record.get_type() {
                RRType::A | RRType::AAAA => !hosts.contains(&name) || used_hosts.contains(&name),
                _ => true,
            }
        });
    }

    /// Ages cached records by the time spent asleep.
    pub(crate) fn age_records(&mut self, elapsed: Duration) {
        let all_records = self
            .ptr
            .values_mut()
            .chain(self.srv.values_mut())
            .chain(self.txt.values_mut())
            .chain(self.addr.values_mut())
            .chain(self.nsec.values_mut())
            .flatten();
        for r in all_records {
            r.record.age_by(elapsed);
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
                        .is_some_and(|ptr| CanonicalName::new(ptr.alias()) == name)
            })
    }

    /// All record types expire through this pass, independently of PTR relationships.
    pub(crate) fn evict_expired(&mut self, now: Instant) -> CacheEviction {
        let mut changed = false;
        let mut expired_addrs: HashMap<String, HashSet<ScopedIp>> = HashMap::new();
        let mut expired_services: HashMap<String, HashSet<String>> = HashMap::new();
        let mut expired_srv = HashSet::new();
        self.retain_records(|record| {
            if !record.record.get_record().is_expired(now) {
                return true;
            }
            changed = true;
            if let Some(addr) = record.record.any().downcast_ref::<DnsAddress>() {
                expired_addrs
                    .entry(record.record.get_name().to_string())
                    .or_default()
                    .insert(addr.address());
            } else if let Some(ptr) = record.record.any().downcast_ref::<DnsPointer>() {
                expired_services
                    .entry(record.record.get_name().to_string())
                    .or_default()
                    .insert(ptr.alias().to_string());
            } else if record.record.get_type() == RRType::SRV {
                expired_srv.insert(CanonicalName::new(record.record.get_name()));
            }
            false
        });
        expired_services.retain(|ty, instances| {
            instances.retain(|instance| {
                !self
                    .pointers(ty, None)
                    .any(|(_, ptr)| CanonicalName::new(ptr.alias()) == CanonicalName::new(instance))
            });
            !instances.is_empty()
        });
        if !expired_srv.is_empty() {
            for (ty, records) in &self.ptr {
                for record in records {
                    if let Some(ptr) = record.record.any().downcast_ref::<DnsPointer>() {
                        if expired_srv.contains(&CanonicalName::new(ptr.alias()))
                            && self.get_srv(ptr.alias()).is_none()
                        {
                            expired_services
                                .entry(ty.clone())
                                .or_default()
                                .insert(ptr.alias().to_string());
                        }
                    }
                }
            }
        }
        CacheEviction {
            changed,
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
                if CanonicalName::new(ty).as_str() == SERVICE_TYPE_ENUMERATION {
                    continue;
                }
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
        self.records()
            .map(|record| {
                let name = CanonicalName::new(record.record.get_name());
                let ty = record.record.get_type();
                let interested = names.contains(&(record.src_intf.index, name.clone(), ty))
                    || ((ty == RRType::A || ty == RRType::AAAA) && hosts.contains(&name));
                let expiry = record.record.get_expire();
                if interested {
                    expiry.min(record.record.get_record().get_refresh_time())
                } else {
                    expiry
                }
            })
            .min()
    }

    pub(crate) fn refresh_due_ptr(&mut self, ty_domain: &str) -> bool {
        let now = Instant::now();

        // Check all PTR records for this ty_domain.
        self.ptr
            .get_mut(CanonicalName::new(ty_domain).as_str())
            .into_iter()
            .flatten()
            .filter_map(|record| record.record.updated_refresh_time(now))
            .count()
            > 0
    }

    pub(crate) fn refresh_due_srv_txt(&mut self, ty_domain: &str) -> HashMap<String, Vec<RRType>> {
        let now = Instant::now();

        let instances: Vec<_> = self
            .ptr
            .get(CanonicalName::new(ty_domain).as_str())
            .into_iter()
            .flatten()
            .filter(|record| !record.record.get_record().is_expired(now))
            .filter_map(|record| {
                record
                    .record
                    .any()
                    .downcast_ref::<DnsPointer>()
                    .map(|ptr| (record.src_intf.index, ptr.alias()))
            })
            .collect();

        let mut refresh_due: HashMap<String, Vec<RRType>> = HashMap::new();
        for (index, instance) in instances {
            for (table, ty) in [(&mut self.srv, RRType::SRV), (&mut self.txt, RRType::TXT)] {
                let refreshed = table
                    .get_mut(CanonicalName::new(instance).as_str())
                    .into_iter()
                    .flatten()
                    .filter(|record| record.src_intf.index == index)
                    .filter_map(|record| record.record.updated_refresh_time(now))
                    .count();
                if refreshed > 0 {
                    refresh_due
                        .entry(instance.to_string())
                        .or_default()
                        .push(ty);
                }
            }
        }
        refresh_due
    }

    pub(crate) fn refresh_due_hosts(&mut self, ty_domain: &str) -> HashSet<String> {
        let now = Instant::now();

        let instances: Vec<_> = self
            .ptr
            .get(CanonicalName::new(ty_domain).as_str())
            .into_iter()
            .flatten()
            .filter(|record| !record.record.get_record().is_expired(now))
            .filter_map(|record| {
                record
                    .record
                    .any()
                    .downcast_ref::<DnsPointer>()
                    .map(|ptr| (record.src_intf.index, ptr.alias()))
            })
            .collect();

        // Collect hostnames we have browsers for by SRV records.
        let mut hostnames_browsed = HashSet::new();
        for (index, instance) in instances {
            let hosts: HashSet<(u32, String)> = self
                .srv
                .get(CanonicalName::new(instance).as_str())
                .into_iter()
                .flatten()
                .filter(|record| record.src_intf.index == index)
                .filter_map(|record| {
                    record
                        .record
                        .any()
                        .downcast_ref::<DnsSrv>()
                        .map(|srv| (index, srv.host().to_string()))
                })
                .collect();

            hostnames_browsed.extend(hosts);
        }
        let mut refresh_due = HashSet::new();
        for (index, hostname) in hostnames_browsed {
            let refreshed = self
                .addr
                .get_mut(CanonicalName::new(&hostname).as_str())
                .into_iter()
                .flatten()
                .filter(|record| record.src_intf.index == index)
                .filter_map(|record| record.record.updated_refresh_time(now))
                .count();

            if refreshed > 0 {
                refresh_due.insert(hostname);
            }
        }
        refresh_due
    }

    pub(crate) fn refresh_due_hostname_resolutions(
        &mut self,
        hostname: &str,
    ) -> HashSet<(String, ScopedIp)> {
        let now = Instant::now();

        self.addr
            .get_mut(CanonicalName::new(hostname).as_str())
            .into_iter()
            .flatten()
            .filter_map(|record| {
                record.record.updated_refresh_time(now)?;

                Some((
                    hostname.to_owned(),
                    record
                        .record
                        .any()
                        .downcast_ref::<DnsAddress>()
                        .unwrap()
                        .address(),
                ))
            })
            .collect()
    }

    pub(crate) fn get_known_answers<'a>(
        &'a self,
        name: &str,
        qtype: RRType,
        now: Instant,
    ) -> Vec<&'a DnsRecordIntf> {
        let records_opt = match qtype {
            RRType::PTR => self.get_ptr(name),
            RRType::SRV => self.get_srv(name),
            RRType::A | RRType::AAAA => self.get_addr(name),
            RRType::TXT => self.get_txt(name),
            _ => None,
        };

        let records = match records_opt {
            Some(items) => items,
            None => return Vec::new(),
        };

        // From RFC 6762 section 7.1:
        // ..Generally, this applies only to Shared records, not Unique records,..
        //
        // ..a Multicast DNS querier SHOULD NOT include
        // records in the Known-Answer list whose remaining TTL is less than
        // half of their original TTL.
        records
            .iter()
            .filter(move |r| {
                r.record.get_type() == qtype
                    && !r.record.get_record().is_expired(now)
                    && !r.record.get_record().is_unique()
                    && !r.record.get_record().halflife_passed(now)
            })
            .collect()
    }

    pub(crate) fn remove_addrs_on_disabled_intf(&mut self, index: u32, ip_type: IpType) {
        self.retain_records(|record| {
            !(record.src_intf.index == index
                && ((record.record.get_type() == RRType::A && ip_type.contains(IpType::V4))
                    || (record.record.get_type() == RRType::AAAA && ip_type.contains(IpType::V6))))
        });
    }

    /// Removes a link's records and returns instances that may need re-resolution.
    /// Subscription reconciliation determines which services have disappeared.
    pub(crate) fn remove_records_on_intf(&mut self, intf: InterfaceId) -> HashSet<String> {
        let mut ptrs = Vec::new();
        let mut modified_instances = HashSet::new();
        let mut hosts = HashSet::new();
        self.retain_records(|record| {
            if record.src_intf.index != intf.index {
                return true;
            }
            let name = CanonicalName::new(record.record.get_name());
            match record.record.get_type() {
                RRType::PTR => {
                    if let Some(ptr) = record.record.any().downcast_ref::<DnsPointer>() {
                        ptrs.push((name.as_str().to_string(), ptr.alias().to_string()));
                    }
                }
                RRType::SRV | RRType::TXT => {
                    modified_instances.insert(name.as_str().to_string());
                }
                RRType::A | RRType::AAAA => {
                    hosts.insert(name);
                }
                _ => {}
            }
            false
        });
        for host in hosts {
            modified_instances.extend(self.get_instances_on_host(host.as_str()));
        }
        let now = Instant::now();
        for (ty, instance) in ptrs {
            if self.has_ptr(&ty, &instance, None, now) {
                modified_instances.insert(instance);
            }
        }
        modified_instances
    }
}

fn apply_cache_flush(incoming: &DnsRecordBox, existing_records: &mut [DnsRecordIntf], index: u32) {
    let now = Instant::now();
    let expiry = now + Duration::from_secs(1);
    for record in existing_records {
        if record.src_intf.index == index
            && incoming.same_rrset(record.record.as_ref())
            && now > record.record.get_created() + Duration::from_secs(1)
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
        assert!(cache.get_ptr_on_intf(ty_domain, intf_b.index).is_some());

        // addr_a was removed, so the instance is in modified_instances.
        assert!(
            result.contains(instance),
            "expected {instance} in modified_instances, got {:?}",
            result
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
            cache.tables().iter().all(|table| table.is_empty()),
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
        assert!(!cache.evict_expired(Instant::now()).changed);
        assert!(cache.get_srv_on_intf(instance, intf.index).is_some());

        let ptr = &cache.get_ptr(ty_domain).unwrap()[0].record;
        let (ptr_expire, ptr_refresh) = (ptr.get_expire(), ptr.get_record().get_refresh_time());

        // Longer than the SRV TTL, shorter than the PTR TTL.
        let slept = Duration::from_secs(60);
        cache.age_records(slept);

        assert!(cache.evict_expired(Instant::now()).changed);
        assert!(
            cache.get_srv_on_intf(instance, intf.index).is_none(),
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
        assert!(cache.tables().iter().all(|table| table.is_empty()));
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
            assert_eq!(cache.rrset_count(), 2);
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
        let record = &cache.get_ptr(name).unwrap()[0];
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
        assert_eq!(cache.srv_count(), 1);
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
        assert_eq!(cache.srv_count(), 1);
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
        assert!(cache.tables().iter().all(|table| table.is_empty()));
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
