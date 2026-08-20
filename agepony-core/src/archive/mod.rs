//! Archive formats: the compact USTAR tar used to bundle several files into one
//! payload, and the signed bundle that pairs a payload with a detached
//! signature. Both are byte-exact ports of Android's `archive/` package, so a
//! bundle made on one platform opens on the other.

pub mod signed_bundle;
pub mod tar;
