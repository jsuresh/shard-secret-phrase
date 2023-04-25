# Specification for Human-Readable Sharding of Secret Passphrases

This document presents a specification, along with a reference implementation, for a scheme that combines Shamir's Secret Sharing (SSS) and BIP39 to securely shard and recover wallet secret phrases. The purpose is to create a secure and interoperable method for backing up Hierarchical Deterministic Wallets, as described in [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

## Table of Contents

* [Abstract](#abstract)
* [Motivation](#motivation)
* [Shamir's Secret Sharing](#shamirs-secret-sharing)
* [Generating and Combining Shares](#generating-and-combining-shares)
* [Reference Implementation](#reference-implementation)
* [References](#references)

## Abstract

This specification aims to provide a standard for an interoperable implementation of Shamir's Secret Sharing (SSS) and a method for its use in securing Hierarchical Deterministic Wallets. SSS enables the division of a master secret into distinct parts that can be distributed among participants. To reconstruct the original secret, a predetermined minimum number of parts must be supplied. Knowledge of fewer than the required number of parts does not reveal information about the master secret.

This specification is an extension on [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), and a simplication of [SLIP-39](https://github.com/satoshilabs/slips/edit/master/slip-0039.md).  It is important to note that the two are not compatible, however, this specification is designed to be a relative *trivial* extension on BIP-39, 
with the goal fostering multiple implementations and an easy path for users
to increase their secret pass phrase security and recoverability with minimal complexity.

## Motivation

The preservation of digital assets is crucial and only becoming more important, especially since there is no recourse in case of a lost wallet secret phrase. The typical approach to safeguarding digital assets involves redundant backups. However, when the asset itself possesses significant and liquidable value, the risk of backup holders absconding with the asset becomes substantial. In this context, the security and storage of the secret phrase location must be carefully managed.

Shamir's Secret Sharing (SSS) offers an improved mechanism for backing up secrets by distributing custodianship among several trusted parties in a manner that can prevent loss, even if one or more parties become compromised. However, the default outputs of SSS are difficult to manage and transfer due to their binary (or hex) encoding. Furthermore, expecting users to migrate their existing wallet seed phrases to a new system that lacks widespread adoption, no matter how secure, is unrealistic.

Thus, we propose a simple standard that leverages existing SSS and BIP39 tooling to generate and assemble human-readable shards, with the goal of facilitating adoption and enhancing overall security in the space.

## Shamir's Secret Sharing

Shamir's Secret Sharing (SSS) is a cryptographic mechanism that allows a secret to be divided into *N* unique parts, where any *T* of them are required to reconstruct the secret. A polynomial *f* of degree *T* - 1 is created, and each participant is given a corresponding point—an integer input *x* to the polynomial and the corresponding output *f*(*x*).

Providing any *T* points will precisely define the polynomial. Typically, the value of the polynomial *f*(0) is used as the shared secret. More details on SSS can be found on [Wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

Given a secret, the user decides how to split it into *N* unique parts such that any *T* parts are sufficient for recovery. Each shard is divided into an array 20-byte fields. The first 19 bytes of each field are dedicated to storing the shard data, while the 20th byte is reserved for specifying the shard length. Once the 20-byte fields are prepared, they are re-encoded using the standard BIP39 encoding scheme.

The user can recover their original entropy by providing *T* shards to assemble the original secret passphrase. We have deliberately chosen to leverage well-tested and well-understood technologies, such as SSS and BIP39, instead of creating our own variants. This choice facilitates multiple implementations and eases onboarding for new users by limiting our design space to simple wrappers.


## Generating and Combining Shares

Both generating and recombing shards relies heavily on the SS algorithm.  We will not rehash the SSS algorithm in this specification - suffice to say it's simple polynomial interpolation that can be done with pen, paper, a calculator and basic calculus knowledge if one so desires

Our thesis is, this simplicity, while maintaining information-theoretic security is integral to our specification as it's a practical defense against vendor lockin.

### Generating Shards

From the passphrase, the original entropy is generated (note that we could also use the original entropy directly; however, we have opted for the passphrase option as most users currently have a BIP39-encoded entropy).

The original entropy is then divided into *T* of *N* shares using the SSS algorithm. Each share is subsequently divided into chunks, whereby each chunk
is exactly 20 bytes in length, each 20 byte chunk is then BIP39 encoded. See [Share Mnemonic Format](share-mnemonic-format) for field specification.

The output is *N* human readable shards they can store
securely as they see fit.

### Assembling Shards

As long as the user has *T* shards, they can reassemble the original entropy. This is achieved by:

1. Splitting each shard into 15-word chunks.
2. Converting each chunk to binary and combining all chunks in a shard together. Each 15 word chunk is a 20 byte field as specified in [Share Mnemonic Format](share-mnemonic-format)
3. Interpolating using SSS with the available chunks to reveal the original entropy.
4. Re-encoding the original entropy from binary back to a set of BIP39-encoded words.

### Share Mnemonic Format

We propose the following format for each share shares:

Share :: [ShareChunk]

ShareChunk ::
    | 0-19 | share as output by SSS |
    | 20   | Length of share in bytes |

Each 20 byte chunk is then BIP39
encoded.

Our design goal was to leverage unchanged existing SSS and BIP39 implementations, this
adds a slight bit of complexity
w.r.t the shard data model, with
the benefit implementations
can lean on existing 'lindy'
open source code for both the
SSS and BIP39 implementations.


## Reference Implementation

This repository contains Golang code that serves as a reference implementation. It is worth noting that the total code length, including checks for invalid input, is approximately 150 lines. This reflects and validates our explicit design decision to keep this specification as lean as possible, leveraging existing standards in an attempt to be skeuomorphic, avoid any kind of lock-in, and remain as easy as possible for both generating and recovering shards.

## References

* [BIP-0032: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
* [Secret Sharing Step by Step by Point Software](http://www.pointsoftware.ch/en/secret-sharing-step-by-step/)
* [SLIP-0039 : Shamir's Secret-Sharing for Mnemonic Codes](https://github.com/satoshilabs/slips/edit/master/slip-0039.md)