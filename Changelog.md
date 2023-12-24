# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased - available on :latest tag for docker image]

Changed:

- Migrate to distroless docker image from scratch

Added:

- New ALLOWED_DEST_FQDN config env parameter for filtering dest FQND based on regex patterns
- New SetIPWhitelist config env paramteter for setting whitelist set of ip addresses which allowed to use proxy connection
- Dependabot version updates automation

## [v0.0.3] - 2021-07-07

Added:

- TZ env varible support for scratch image

Changed:

- Update golang to 1.16.5
- Migrate to go module

## [v0.0.2] - 2020-03-21

Added:

- PROXY_PORT env parameter for app
- Multiarch support for docker images

Changed:

ADd caarlos0/env lib for working with ENV variables

## [v0.0.1] - 2018-04-24

Added:

- Optional auth

Changed:

- Golang vendoring
- Change Dockerfile for multistage builds with final scratch image

### Removed

- IDE files
