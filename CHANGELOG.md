# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Changed `web_push_native::Auth` from `GenericArray<u8, U16>` to `[u8; 16]`, required by the RustCrypto ecosystem moving away from `generic-array`
- Update public re-exports, `p256` from 0.13.2 to 0.14.0 and `jwt-simple` from 0.12.17 to 0.15.0
- Bump MSRV for `web-push-native` and `ece-native` to 1.89.0

For `web-push-native` these are breaking changes, but the required migrations should be relatively simple. Concretely, the recommended way of generating an `Auth` value has changed:

```diff
- let auth = Auth::clone_from_slice(slice);
+ let auth = Auth::try_from(slice)?;
```

Also, the public reexport `p256` has received some significant API changes in version 0.14.0. In particular, the recommended way of generating random values is now the [`crypto_common::Generate`](https://docs.rs/crypto-common/latest/crypto_common/trait.Generate.html) trait, exported as `p256::elliptic_curve::Generate` and `sec1::ToEncodedPoint` has been renamed to `sec1::ToSec1Point`. For other API changes, please refer to the upstream [CHANGELOG](https://github.com/RustCrypto/elliptic-curves/blob/master/p256/CHANGELOG.md).
The public `jwt-simple` crate has also received semver-incompatible changes, but for most users there should not be a need to apply any migrations beyond updating the crate.

### Fixed

- Fix possible panic when deserializing a PushSubscription object with a wrong-length auth entry to a `web_push_native::WebPushBuilder`

### Security

- Mitigate [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) by updating RustCrypto dependencies

## [0.5.0] - 2026-07-26

### Added

- Make `web_push_native::vapid` public exposing `VapidAuthorization` and `VapidSignature` to the user

### Changed

- Bump MSRV for `web-push-native` to 1.87.0
- Bump MSRV for `ece-native` to 1.66.1

### Fixed

- Fix panic in nonce sequence number generation on 32-bit platforms in `ece_native::encrypt` and `ece_native::decrypt`

## [0.4.0] - 2023-12-25

### Changed

- Switch to `hyper` 1.1.0 from 0.14.27 and `http` 1.0.0 from `0.2.9`

## [0.3.0] - 2023-10-01

### Removed

- Remove `ece_native::Error::PrefixLengthInvalid` error variant

### Fixed

- Fix possible panic due to attempted out-of-bounds array access in `ece_native::decrypt`

<!-- ### Added -->
<!-- ### Changed -->
<!-- ### Deprecated -->
<!-- ### Removed -->
<!-- ### Fixed -->
<!-- ### Security -->
