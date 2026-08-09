use nre_policy_guest::PolicyAction;

use crate::{
    GeoFailurePolicy, GeoHandle, GeoLookup, GeoProvider, GeoRule, GeoStatus, IpAddress, PolicySet,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAuthentication {
    Socket,
    ProxyProtocol,
    Relay,
    UntrustedForwardedHeader,
    Missing,
}

impl SourceAuthentication {
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Self::Socket | Self::ProxyProtocol | Self::Relay)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedSource {
    pub address: IpAddress,
    pub authentication: SourceAuthentication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    UnauthenticatedSource,
    SharedDeny,
    OverlayDeny,
    GeoDeny,
    SharedAllow,
    OverlayAllow,
    GeoAllow,
    DefaultAllow,
    DefaultDeny,
    GeoMissing,
    GeoExpired,
    GeoInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub action: PolicyAction,
    pub reason: DecisionReason,
    pub geo_status: GeoStatus,
}

pub struct IpPolicy<'a, const MAX_NODES: usize> {
    pub shared: &'a PolicySet<MAX_NODES>,
    pub overlay: Option<&'a PolicySet<MAX_NODES>>,
    pub geo_rules: &'a [GeoRule],
    pub geo_handle: Option<GeoHandle<'a>>,
    pub geo_failure: GeoFailurePolicy,
    pub default: RuleEffect,
}

impl<const MAX_NODES: usize> IpPolicy<'_, MAX_NODES> {
    pub fn evaluate<P: GeoProvider>(&self, source: TrustedSource, provider: &P) -> Decision {
        if !source.authentication.is_authenticated() {
            return decision(
                PolicyAction::Deny,
                DecisionReason::UnauthenticatedSource,
                GeoStatus::NotRequested,
            );
        }

        // Deny is evaluated across both independent policy layers before any
        // allow branch, so an overlay can never weaken a shared deny.
        if self.shared.contains(source.address, RuleEffect::Deny) {
            return decision(
                PolicyAction::Deny,
                DecisionReason::SharedDeny,
                GeoStatus::NotRequested,
            );
        }
        if self
            .overlay
            .is_some_and(|overlay| overlay.contains(source.address, RuleEffect::Deny))
        {
            return decision(
                PolicyAction::Deny,
                DecisionReason::OverlayDeny,
                GeoStatus::NotRequested,
            );
        }

        let geo = self.evaluate_geo(source.address, provider);
        if let Some(result) = geo.decision
            && result.action == PolicyAction::Deny
        {
            return result;
        }

        if self.shared.contains(source.address, RuleEffect::Allow) {
            return decision(PolicyAction::Allow, DecisionReason::SharedAllow, geo.status);
        }
        if self
            .overlay
            .is_some_and(|overlay| overlay.contains(source.address, RuleEffect::Allow))
        {
            return decision(
                PolicyAction::Allow,
                DecisionReason::OverlayAllow,
                geo.status,
            );
        }
        if let Some(result) = geo.decision {
            return result;
        }
        match self.default {
            RuleEffect::Allow => decision(
                PolicyAction::Allow,
                DecisionReason::DefaultAllow,
                geo.status,
            ),
            RuleEffect::Deny => {
                decision(PolicyAction::Deny, DecisionReason::DefaultDeny, geo.status)
            }
        }
    }

    fn evaluate_geo<P: GeoProvider>(&self, address: IpAddress, provider: &P) -> GeoEvaluation {
        if self.geo_rules.is_empty() {
            return GeoEvaluation {
                decision: None,
                status: GeoStatus::NotRequested,
            };
        }
        let Some(handle) = self.geo_handle else {
            return self.geo_failure(GeoStatus::Missing, DecisionReason::GeoMissing);
        };
        match provider.lookup(handle, address) {
            GeoLookup::Found(record) => {
                for effect in [RuleEffect::Deny, RuleEffect::Allow] {
                    if self
                        .geo_rules
                        .iter()
                        .any(|rule| rule.effect == effect && rule.matches(record))
                    {
                        return GeoEvaluation {
                            decision: Some(match effect {
                                RuleEffect::Deny => decision(
                                    PolicyAction::Deny,
                                    DecisionReason::GeoDeny,
                                    GeoStatus::Fresh,
                                ),
                                RuleEffect::Allow => decision(
                                    PolicyAction::Allow,
                                    DecisionReason::GeoAllow,
                                    GeoStatus::Fresh,
                                ),
                            }),
                            status: GeoStatus::Fresh,
                        };
                    }
                }
                GeoEvaluation {
                    decision: None,
                    status: GeoStatus::Fresh,
                }
            }
            GeoLookup::Missing => self.geo_failure(GeoStatus::Missing, DecisionReason::GeoMissing),
            GeoLookup::Expired => self.geo_failure(GeoStatus::Expired, DecisionReason::GeoExpired),
            GeoLookup::Invalid => self.geo_failure(GeoStatus::Invalid, DecisionReason::GeoInvalid),
        }
    }

    fn geo_failure(&self, status: GeoStatus, reason: DecisionReason) -> GeoEvaluation {
        let action = match self.geo_failure {
            GeoFailurePolicy::Allow => PolicyAction::Allow,
            GeoFailurePolicy::Deny => PolicyAction::Deny,
        };
        GeoEvaluation {
            decision: Some(decision(action, reason, status)),
            status,
        }
    }
}

#[derive(Clone, Copy)]
struct GeoEvaluation {
    decision: Option<Decision>,
    status: GeoStatus,
}

const fn decision(action: PolicyAction, reason: DecisionReason, geo_status: GeoStatus) -> Decision {
    Decision {
        action,
        reason,
        geo_status,
    }
}
