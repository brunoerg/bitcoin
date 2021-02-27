#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Anchors functionality"""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

import os

def check_node_connections(*, node, num_in, num_out):
    info = node.getnetworkinfo()
    assert_equal(info["connections_in"], num_in)
    assert_equal(info["connections_out"], num_out)


class AnchorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.log.info("Add 2 block-relay-only connections to node 0")
        for i in range(2):
            self.log.info(f"block-relay-only: {i}")
            self.nodes[0].add_outbound_p2p_connection(P2PInterface(), p2p_idx=i, connection_type="block-relay-only")
        
        self.log.info("Check node connections")
        check_node_connections(node=self.nodes[0], num_in=0, num_out=2)

        self.log.info("Stop node 0")
        self.stop_node(0)

        self.log.info("Check anchors.dat file in node directory")
        assert os.path.exists(os.path.join(self.nodes[0].datadir + '/regtest', 'anchors.dat'))

        self.log.info("Start node 0")
        self.start_node(0)

        self.log.info("When node starts, check if anchors.dat doesn't exist anymore")
        assert not os.path.exists(os.path.join(self.nodes[0].datadir + '/regtest', 'anchors.dat'))

        self.log.info(self.nodes[0].getpeerinfo())


if __name__ == '__main__':
    AnchorsTest().main()
