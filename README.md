# go-asn1utils

[![Go CI](https://github.com/gomaja/go-asn1utils/actions/workflows/ci.yml/badge.svg)](https://github.com/gomaja/go-asn1utils/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gomaja/go-asn1utils.svg)](https://pkg.go.dev/github.com/gomaja/go-asn1utils)
[![Go Report Card](https://goreportcard.com/badge/github.com/gomaja/go-asn1utils)](https://goreportcard.com/report/github.com/gomaja/go-asn1utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=gomaja_go-asn1utils&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=gomaja_go-asn1utils)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=gomaja_go-asn1utils&metric=coverage)](https://sonarcloud.io/summary/new_code?id=gomaja_go-asn1utils)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=gomaja_go-asn1utils&metric=bugs)](https://sonarcloud.io/summary/new_code?id=gomaja_go-asn1utils)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=gomaja_go-asn1utils&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=gomaja_go-asn1utils)

## Description

`go-asn1utils` is a Go library designed to facilitate the manipulation of ASN.1 encoded data. Its primary functionality is to convert ASN.1 bytes—which may use BER (Basic Encoding Rules) features like indefinite lengths—into DER (Distinguished Encoding Rules) compliant bytes.

Key features include:
- Parsing ASN.1 structures with support for both definite and indefinite length encodings.
- Handling constructed and primitive types.
- Canonicalizing output to strict DER format, including:
  - Normalizing boolean values.
  - Flattening constructed forms of primitive types (e.g., OCTET STRING, BIT STRING).
  - Sorting elements in SET types.

This utility ensures that ASN.1 data is represented in a canonical form, suitable for cryptographic operations such as signing and verification where a unique encoding is required.
