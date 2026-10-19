// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_PSBT_H
#define BITCOIN_TEST_FUZZ_UTIL_PSBT_H

#include <cstddef>
#include <cstdint>

/**
 * Structure-aware custom mutator for raw (binary) PSBTs, covering both the
 * BIP 174 (v0) and BIP 370 (v2) wire formats.
 *
 * Random byte-level mutation rarely produces a well-formed key-value map, so
 * this mutator parses the input into maps of records, applies 1-3 mutations
 * (mutate a record's key or value, remove/duplicate a record, insert a
 * well-known field, add/remove a whole map) and reserializes. Inputs that do
 * not parse as a PSBT container at all are replaced by a minimal valid v0 or
 * v2 template.
 *
 * Ported from bitcoinfuzz's PSBT custom mutator.
 */
size_t PSBTCustomMutator(uint8_t* data, size_t size, size_t max_size, unsigned int seed);

#endif // BITCOIN_TEST_FUZZ_UTIL_PSBT_H
