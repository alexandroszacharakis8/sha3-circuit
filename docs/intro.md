# Docs 

This document focuses on the techniques and the choices for implementing the [keccak-f[1600]](https://keccak.team/keccak_specs_summary.html) permutation in-circuit. 

The chip can be used in a straightforward way to instantiate the sha3-256 and the keccak-256 (the variation used by [Ethereum](https://ethereum.org/)) hash functions. 

The goal of this implementation is to minimize *proof-size* but without blowing-up the prover. Roughly, the goal is to use ~10 advice columns and parallel lookups to achieve the required balance.

The main challenges are handling efficiently the required field operations (XORs, ANDs, rotations etc) on the native field of the snark. The core technique we use is [packed arithmetic](techniques.md#packed-arithmetic) -similar to [zcash sha256 implementation](https://atheartengineer.github.io/halo2/design/gadgets/sha256.html) and other projects- which essentially means using a redundant representation for bits. This redundant representation, when combined with lookup tables, allows to implement bitwise operations as native field operations.

Here we make the assumption that the field is *big enough to represent a spead lane*. Concretely, since a lane is 64 bits and we represent each bit with 3 bits, we assume that the field size is at least 192 bits.

## The keccak-f permutation

A detailed description for the keecak-f permutation can be found [on the keccak team site](https://keccak.team/keccak_specs_summary.html). We also include a [short, informal description](./keccakf.md) where we omit some details that are not important for this repo.

## Technique overview

We present [here](./techniques.md) the core techniques used for the in-circuit implementation of keccak-f. Essentially, we describe how to overcome the main two issues using lookups:

1. doing bitwise operations (AND, XOR, NOT), and
2. doing bit rotation operations.


## Chip overview 

The chip consists of various subconfigs that share columns and are designed to do specialized operations. It depends on a [single lookup table](lookup.md) that contains *dense/spread* mapping along with a tag to restrict the bit size of a lookup entry.

The following subconfigs are used:

- a [bytes to spread subconfig](bytes_to_spread_subconfig.md) that does the conversion between a 64bit spread lane and dense bytes, 
- a [decomposition subconfig](decomposition_subconfig.md) that decomposes a dense lane into limbs of appropriate size to support specific rotations, 
- an [auxiliary linear combination subconfig](aux_lc_subconfig.md) that allows verifying linear combinations (on the native field) of spread bytes to implement bit-wise arithmetic, 
- a [bootstrap subconfig](bootstrap_subconfig.md) that takes a spread lane with errors and gives the corresponding spread lane without errors, 
- a [keccak operations subconfig](keecak_operations_subconfig.md) that does not introduce new constraints, but rather uses the above subconfigs to implement the core keccak operations 
and implement a round of the permutation in circuit.

## Implementing the hash functions

Given the keccak-f chip, it is straightforward to implement the two hash functions. They are essentially a standard [sponge construction](https://en.wikipedia.org/wiki/Sponge_function). Roughly, what is done is:

1. pad the message (depending on the hash function choice) to force it to be of length $k\cdot 1088$ bits and arrange it in 64-bit lanes,
2. initialize the state with 0s,
3. absorb 17 lanes from the input message (xor with the state),
4. perform the keccak-f permutation,
5. repeat steps 3,4 until you have absorbed all message lanes,
6. output the first four elements of the final state as the hash.

That said, we make some changes to get improved efficiency. Specifically, we want to minimize the number of "bootstrapping" operations we perform, since each requires two or three rows.

- We don't explicitely xor the message with the state. Instead, when perform the $\chi$ [step](keccakf) on the *last round* of a keccak-f execution, we also xor the message for the next block as part of the $\chi$ operation.
- We don't do the $\iota$ step directly. Rather, at the begining of a round we xor the round constant *of the previous round* when computing the $\theta$ [step](keccakf). After the 
final round, we perform the final $\iota$ [step](keccakf) normally.

Essentially, we leverage the fact that XOR commutes and save a few rows by "squashing" this operations to other operations that have room for more error.
