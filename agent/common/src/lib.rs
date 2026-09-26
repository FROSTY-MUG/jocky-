//! JOCKY DFIR common library.
//!
//! Single source of truth for the on-wire protocol shapes (`protocol`),
//! cryptographically signed consent tokens (`consent`), and the signed build
//! manifest attestation (`manifest`) used to attest agent binaries. All
//! execution on the JOCKY platform is consent-bound: an `Agent` must present a
//! valid, team-issued `ConsentToken` before performing any forensic operation.

pub mod consent;
pub mod manifest;
pub mod protocol;
pub mod constants;