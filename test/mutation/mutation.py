#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import pathlib
import os
import subprocess


FILE_MUTATE_AND_SCRIPT_TEST = [
    ['src/node/coin.cpp', './test/functional/rpc_fundrawtransaction.py']
]

# you should add the ';' for each command
SCRIPT_TO_COMPILE = 'make clean; make;'

BASE_PATH = str(pathlib.Path().resolve())
MUTATION_PATH = f"{BASE_PATH}/test/mutation"


def mkdir_mutation_folder():
    path = os.path.join(f'{BASE_PATH}/test/mutation/', 'muts')
    if not os.path.isdir(f'{BASE_PATH}/test/mutation/muts'):
        os.mkdir(path)

def mutate():
    with open(f"{MUTATION_PATH}/mutate.out", "w") as f:
        for (file_to_mutate, script_to_test) in FILE_MUTATE_AND_SCRIPT_TEST:
            r = subprocess.call(["mutate", file_to_mutate, "--mutantDir", f"{BASE_PATH}/test/mutation/muts", "--noCheck"],
                                stdout=f, stderr=f)
            assert r == 0

def analyze():
    with open(f"{MUTATION_PATH}/analyze.out", "w") as f:
        for (file_to_mutate, script_to_test) in FILE_MUTATE_AND_SCRIPT_TEST:
            r = subprocess.call(
                ["analyze_mutants", f"{BASE_PATH}/{file_to_mutate}", f"{SCRIPT_TO_COMPILE} {script_to_test}",
                 "--mutantDir", f"{BASE_PATH}/test/mutation/muts", "--timeout", "12000"],
                stdout=f, stderr=f
            )
    
    with open(f"{MUTATION_PATH}/analyze.out", 'r') as f:
        lineCount = 0
        notKilledCount = 0
        killedCount = 0
        mutationScore = -1
        for line in f:
            lineCount += 1
            if "NOT KILLED" in line:
                notKilledCount += 1
            elif "KILLED" in line:
                killedCount += 1
            if "MUTATION SCORE" in line:
                mutationScore = float(line.split()[2])
        print("Results.:")
        print(notKilledCount)
        print(killedCount)


if __name__ == "__main__":
    mkdir_mutation_folder()
    mutate()
    analyze()
