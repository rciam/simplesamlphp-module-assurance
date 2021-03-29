# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Comply to [PSR-4: Autoloader](https://www.php-fig.org/psr/psr-4/) guidelines
- Comply to [PSR-1: Basic Coding Standard](https://www.php-fig.org/psr/psr-1/) guidelines
- Comply to [PSR-12: Extended Coding Style](https://www.php-fig.org/psr/psr-12/) guidelines

## [v1.0.2] - 2021-03-23

### Added

- Support for specifying a list of assurance values (`minAssurance` config option), one of which MUST be present in the evaluated assurance attribute

## [v1.0.1] - 2021-03-17

### Fixed

- Bug in processing regex mapping rules for pass-through assurance values

## [v1.0.0] - 2021-02-26

This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added

- DynamicAssurance class
  - Determinate Level of Assurance based on:
    - assurance attribute values associated with the authentication event
    - idpTags
    - idpPolicies
    - entitlement values associated with the authentication event
  - Add dynamic initialization of configuration options
- IdPAuthnContextClassRef class
  - Saves the IdP AuthnContextClassRef in the SAML 2 response
- SPAuthnContextClassRef class
  - Saves the SP AuthnContextClassRef in the SAML 2 response

### Fixed

- Fix code style
