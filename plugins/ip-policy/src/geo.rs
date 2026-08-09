use crate::IpAddress;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeoHandle<'a> {
    pub id: &'a str,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeoRecord {
    pub country: [u8; 2],
    pub region: Option<[u8; 3]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoStatus {
    NotRequested,
    Fresh,
    Missing,
    Expired,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoLookup {
    Found(GeoRecord),
    Missing,
    Expired,
    Invalid,
}

pub trait GeoProvider {
    fn lookup(&self, handle: GeoHandle<'_>, address: IpAddress) -> GeoLookup;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeoRule {
    pub country: [u8; 2],
    pub region: Option<[u8; 3]>,
    pub effect: crate::RuleEffect,
}

impl GeoRule {
    pub fn matches(self, record: GeoRecord) -> bool {
        self.country == record.country
            && self
                .region
                .is_none_or(|region| Some(region) == record.region)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoFailurePolicy {
    Allow,
    Deny,
}
