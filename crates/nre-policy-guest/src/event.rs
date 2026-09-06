use crate::abi_generated::field;
use crate::wire::invalid_wire;
use crate::{
    FrameWriter, GuestError, PolicyDomainSource, SecurityEventAction, SecurityEventCode,
    SecurityEventReason,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicySecurityEvent {
    pub code: SecurityEventCode,
    pub action: SecurityEventAction,
    pub rule_index: u32,
    pub dataset_index: u32,
    pub classification_index: u32,
    pub outbound_index: u32,
    pub reason: SecurityEventReason,
    pub domain_source: PolicyDomainSource,
}

impl PolicySecurityEvent {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, GuestError> {
        self.validate()?;
        let mut writer = FrameWriter::new(output);
        writer.write_varint_field(field::emit_event_request::CODE, self.code as u64)?;
        writer.write_varint_field(field::emit_event_request::ACTION, self.action as u64)?;
        if self.rule_index != 0 {
            writer.write_varint_field(
                field::emit_event_request::RULE_INDEX,
                self.rule_index as u64,
            )?;
        }
        if self.dataset_index != 0 {
            writer.write_varint_field(
                field::emit_event_request::DATASET_INDEX,
                self.dataset_index as u64,
            )?;
        }
        if self.classification_index != 0 {
            writer.write_varint_field(
                field::emit_event_request::CLASSIFICATION_INDEX,
                self.classification_index as u64,
            )?;
        }
        if self.outbound_index != 0 {
            writer.write_varint_field(
                field::emit_event_request::OUTBOUND_INDEX,
                self.outbound_index as u64,
            )?;
        }
        if self.reason != SecurityEventReason::None {
            writer.write_varint_field(field::emit_event_request::REASON, self.reason as u64)?;
        }
        if self.domain_source != PolicyDomainSource::Unspecified {
            writer.write_varint_field(
                field::emit_event_request::DOMAIN_SOURCE,
                self.domain_source as u64,
            )?;
        }
        Ok(writer.len())
    }

    fn validate(self) -> Result<(), GuestError> {
        if [
            self.rule_index,
            self.dataset_index,
            self.classification_index,
            self.outbound_index,
        ]
        .iter()
        .any(|index| *index > 65_535)
            || (self.classification_index != 0 && self.dataset_index == 0)
        {
            return Err(invalid_wire());
        }
        let valid = match self.code {
            SecurityEventCode::WafRuleMatch => {
                matches!(
                    self.action,
                    SecurityEventAction::Observe | SecurityEventAction::Deny
                ) && self.reason == SecurityEventReason::None
                    && self.dataset_index == 0
                    && self.classification_index == 0
                    && self.outbound_index == 0
                    && self.domain_source == PolicyDomainSource::Unspecified
            }
            SecurityEventCode::IpRuleMatch => {
                matches!(
                    self.action,
                    SecurityEventAction::Observe
                        | SecurityEventAction::Deny
                        | SecurityEventAction::Allow
                ) && self.outbound_index == 0
                    && self.domain_source == PolicyDomainSource::Unspecified
                    && matches!(
                        self.reason,
                        SecurityEventReason::None | SecurityEventReason::CoverageUnknown
                    )
            }
            SecurityEventCode::IpCheckFailure => {
                matches!(
                    self.action,
                    SecurityEventAction::Observe | SecurityEventAction::Deny
                ) && self.reason != SecurityEventReason::None
                    && self.outbound_index == 0
                    && self.domain_source == PolicyDomainSource::Unspecified
            }
            SecurityEventCode::RoutingRuleMatch => {
                matches!(
                    self.action,
                    SecurityEventAction::Deny
                        | SecurityEventAction::Direct
                        | SecurityEventAction::Upstream
                ) && self.reason == SecurityEventReason::None
                    && (self.action == SecurityEventAction::Upstream) == (self.outbound_index != 0)
            }
            SecurityEventCode::RoutingFailure => {
                self.action == SecurityEventAction::Deny && self.reason != SecurityEventReason::None
            }
            SecurityEventCode::Unspecified => false,
        };
        if valid { Ok(()) } else { Err(invalid_wire()) }
    }
}
