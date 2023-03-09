use std::fmt::Debug;

use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;
use crate::{Error, NamedGroup};

/// *ring* based CryptoProvider.
pub mod ring;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// KeyExchange operations that are supported by the provider.
    type KeyExchange: KeyExchange;

    /// Build a ticket generator.
    fn ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed>;

    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Verify that the two input slices are equal, in constant time.
    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool;
}

pub enum KeyExchangeError {
    UnsupportedGroup,
    KeyExchangeFailed(GetRandomFailed),
}

/// KeyExchange supports performing a key exchange with a peer using a supported group.
pub trait KeyExchange: Send + Sync + 'static {
    type SupportedGroup: SupportedGroup;

    fn all_supported_groups() -> &'static [&'static Self::SupportedGroup];

    fn choose(
        name: NamedGroup,
        supported: &[&'static Self::SupportedGroup],
    ) -> Result<Self, KeyExchangeError>
    where
        Self: Sized;

    fn start(skxg: &'static Self::SupportedGroup) -> Result<Self, GetRandomFailed>
    where
        Self: Sized;

    fn group(&self) -> NamedGroup;
    fn pubkey(&self) -> &[u8];
    fn complete<T>(self, peer: &[u8], f: impl FnOnce(&[u8]) -> Result<T, ()>) -> Result<T, Error>;
}

pub trait SupportedGroup: Clone + Debug + Send + Sync + 'static {
    fn name(&self) -> NamedGroup;
}
