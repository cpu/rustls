use alloc::vec::Vec;

use pki_types::EchConfigListBytes;

use crate::crypto::hpke::{Hpke, HpkeSuite};
#[cfg(feature = "logging")]
use crate::log::{debug, warn};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::EchConfig as EchConfigMsg;
use crate::{EncryptedClientHelloError, Error};

/// Configuration for performing encrypted client hello.
///
/// Note: differs from the protocol-encoded EchConfig (`EchConfigMsg`).
#[derive(Clone, Debug)]
pub struct EchConfig {
    /// The selected EchConfig.
    pub(crate) config: EchConfigMsg,

    /// An HPKE instance corresponding to a suite from the `config` we have selected as
    /// a compatible choice.
    pub(crate) suite: &'static dyn Hpke,
}

impl EchConfig {
    /// Construct an EchConfig by selecting a ECH config from the provided bytes that is compatible
    /// with one of the given HPKE suites.
    ///
    /// The config list bytes should be sourced from a DNS-over-HTTPS lookup resolving the `HTTPS`
    /// resource record for the host name of the server you wish to connect via ECH,
    /// and extracting the ECH configuration from the `ech` parameter. The extracted bytes should
    /// be base64 decoded to yield the `EchConfigListBytes` you provide to rustls.
    ///
    /// One of the provided ECH configurations must be compatible with the HPKE provider's supported
    /// suites or an error will be returned.
    ///
    /// See the [ech-client.rs] example for a complete example of fetching ECH configs from DNS.
    ///
    /// [ech-client.rs]: https://github.com/rustls/rustls/blob/main/provider-example/examples/ech-client.rs
    pub fn new(
        ech_config_list: EchConfigListBytes<'_>,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let ech_configs =
            Vec::<EchConfigMsg>::read(&mut Reader::init(&ech_config_list)).map_err(|_| {
                Error::InvalidEncryptedClientHello(EncryptedClientHelloError::InvalidConfigList)
            })?;
        let (config, suite) = Self::select_config_and_suite(ech_configs, hpke_suites)?;

        Ok(Self { config, suite })
    }

    fn select_config_and_suite(
        configs: Vec<EchConfigMsg>,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<(EchConfigMsg, &'static dyn Hpke), Error> {
        // Note: we name the index var _i because if the log feature is disabled
        //       it is unused.
        #[cfg_attr(not(feature = "std"), allow(clippy::unused_enumerate_index))]
        for (_i, config) in configs.iter().enumerate() {
            let contents = match config {
                EchConfigMsg::V18(contents) => contents,
                EchConfigMsg::Unknown {
                    version: _version, ..
                } => {
                    warn!(
                        "ECH config {} has unsupported version {:?}",
                        _i + 1,
                        _version
                    );
                    continue; // Unsupported version.
                }
            };

            if contents.has_unknown_mandatory_extension() || contents.has_duplicate_extension() {
                warn!("ECH config has duplicate, or unknown mandatory extensions: {contents:?}",);
                continue; // Unsupported, or malformed extensions.
            }

            let key_config = &contents.key_config;
            for cipher_suite in &key_config.symmetric_cipher_suites {
                if cipher_suite.aead_id.tag_len().is_none() {
                    continue; // Unsupported EXPORT_ONLY AEAD cipher suite.
                }

                let suite = HpkeSuite {
                    kem: key_config.kem_id,
                    sym: *cipher_suite,
                };
                if let Some(hpke) = hpke_suites
                    .iter()
                    .find(|hpke| hpke.suite() == suite)
                {
                    debug!(
                        "selected ECH config ID {:?} suite {:?}",
                        key_config.config_id, suite
                    );
                    return Ok((config.clone(), *hpke));
                }
            }
        }

        Err(EncryptedClientHelloError::NoCompatibleConfig.into())
    }
}
