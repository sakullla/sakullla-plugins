#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    ZeroInterval,
    ZeroBurst,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketSpec {
    pub emission_interval_ns: u64,
    pub burst: u32,
}

impl BucketSpec {
    pub const fn validate(self) -> Result<Self, ConfigError> {
        if self.emission_interval_ns == 0 {
            return Err(ConfigError::ZeroInterval);
        }
        if self.burst == 0 {
            return Err(ConfigError::ZeroBurst);
        }
        if self
            .emission_interval_ns
            .checked_mul((self.burst - 1) as u64)
            .is_none()
        {
            return Err(ConfigError::ArithmeticOverflow);
        }
        Ok(self)
    }

    const fn tolerance_ns(self) -> u64 {
        self.emission_interval_ns * (self.burst - 1) as u64
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GcraState {
    theoretical_arrival_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preview {
    pub allowed: bool,
    pub retry_after_ns: u64,
    pub(crate) next_theoretical_arrival_ns: u64,
}

impl GcraState {
    pub const fn new() -> Self {
        Self {
            theoretical_arrival_ns: 0,
        }
    }

    pub fn preview(self, now_ns: u64, spec: BucketSpec) -> Result<Preview, ConfigError> {
        let spec = spec.validate()?;
        let earliest = self
            .theoretical_arrival_ns
            .saturating_sub(spec.tolerance_ns());
        if now_ns < earliest {
            return Ok(Preview {
                allowed: false,
                retry_after_ns: earliest - now_ns,
                next_theoretical_arrival_ns: self.theoretical_arrival_ns,
            });
        }
        let base = self.theoretical_arrival_ns.max(now_ns);
        let next = base
            .checked_add(spec.emission_interval_ns)
            .ok_or(ConfigError::ArithmeticOverflow)?;
        Ok(Preview {
            allowed: true,
            retry_after_ns: 0,
            next_theoretical_arrival_ns: next,
        })
    }

    pub fn commit(&mut self, preview: Preview) {
        if preview.allowed {
            self.theoretical_arrival_ns = preview.next_theoretical_arrival_ns;
        }
    }
}
