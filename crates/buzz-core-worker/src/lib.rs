#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(async_fn_in_trait)]
//! Bounded execution seams for the hardened Core worker host.

/// One-page connector worker execution contracts.
pub mod connector_iteration;
/// Core CRM known-record provider composition.
pub mod core_crm_provider;
/// Production read-only Core CRM database and provider composition.
pub mod postgres_core_crm;
