// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <hash.h>
#include <protocol.h>
#include <node/txreconciliation.h>
#include <test/util/setup_common.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>

namespace {

void initialize_txreconciliation()
{
    static const auto testing_setup = MakeNoLogFileContext<>(ChainType::MAIN);
}

} // namespace

FUZZ_TARGET(txreconciliation, .init = initialize_txreconciliation)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    CSipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    TxReconciliationTracker tracker(TXRECONCILIATION_VERSION, hasher);

    const int64_t num_peers{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 150)};
    for (int64_t i = 0; i < num_peers; i++) {
        tracker.PreRegisterPeer(i);
    }

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100) {
        auto node_id{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 1000)};
        auto peer_recon_version{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
        auto remote_salt{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
        auto is_peer_inbound{fuzzed_data_provider.ConsumeBool()};
        auto register_peer{tracker.RegisterPeer(node_id, is_peer_inbound, peer_recon_version, remote_salt)};

        if (register_peer == ReconciliationRegisterResult::SUCCESS) {
            assert(node_id < num_peers);
            assert(peer_recon_version >= TXRECONCILIATION_VERSION);
            if (fuzzed_data_provider.ConsumeBool()) {
                (void)tracker.ForgetPeer(node_id, is_peer_inbound);
            }
        } else if (register_peer == ReconciliationRegisterResult::ALREADY_REGISTERED) {
            assert(node_id < num_peers);
        } else if (register_peer == ReconciliationRegisterResult::PROTOCOL_VIOLATION) {
            assert(peer_recon_version < TXRECONCILIATION_VERSION);
        }
    }

    Wtxid wtxid{Wtxid::FromUint256(ConsumeUInt256(fuzzed_data_provider))};
    NodeId node_id{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 1000)};
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 3000) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                wtxid = Wtxid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
            },
            [&] {
                node_id = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 1000);
            },
            [&] {
                (void)tracker.AddToSet(node_id, wtxid);
            },
            [&] {
                (void)tracker.TryRemovingFromSet(node_id, wtxid);
            },
            [&] {
                (void)tracker.IsPeerRegistered(node_id);
            }
        );
    }
}
