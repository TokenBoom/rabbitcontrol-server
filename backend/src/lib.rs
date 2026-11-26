#![deny(unsafe_code)]

pub mod api;
pub mod auth;
pub mod ephemeral;
pub mod generated {
    pub mod error_codes;
}
pub mod net;
pub mod pki;
pub mod relay;
pub mod signal;
pub mod store;

pub use net::{bind_tcp_listener, DEFAULT_TCP_LISTEN_BACKLOG};

#[cfg(test)]
mod tests {
    use crate::generated::error_codes;

    #[test]
    fn generated_spec_error_codes_self_consistent() {
        assert!(!error_codes::SPEC_VERSION.is_empty());
        assert!(!error_codes::ALL_CANONICAL_CODES.is_empty());
        assert!(!error_codes::WIRE_ALIAS_MAP.is_empty());

        for &canonical in error_codes::ALL_CANONICAL_CODES {
            assert_eq!(
                error_codes::canonical_for_wire(canonical),
                Some(canonical),
                "canonical code must resolve to itself: {canonical}"
            );
            assert!(
                error_codes::primary_wire_alias(canonical).is_some(),
                "canonical code missing primary wire alias: {canonical}"
            );
        }

        for &(alias, canonical) in error_codes::WIRE_ALIAS_MAP {
            assert!(
                error_codes::ALL_CANONICAL_CODES.contains(&canonical),
                "wire alias {alias} maps to unknown canonical code {canonical}"
            );
            assert_eq!(
                error_codes::canonical_for_wire(alias),
                Some(canonical),
                "wire alias {alias} did not resolve to {canonical}"
            );
        }
    }
}
