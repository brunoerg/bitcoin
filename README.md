## This is the artifact for the paper "An empirical evaluation of fuzz targets using mutation testing" accepted at SAST 2025.

The artifact accompanying this paper is a fully functional fork of Bitcoin Core, extended to support both fuzz testing and mutation testing of its existing fuzz targets. All experiments reported in “An empirical evaluation of fuzz targets using mutation testing” were performed on this modified Bitcoin Core codebase.

To reproduce our results, please follow these steps:

1. Clone and prepare the repository
  Obtain our fork of Bitcoin Core (which includes the fuzz targets and mutation hooks).

2. Build with fuzzing enabled
  Follow the fuzzing build instructions in doc/fuzzing.md. For OS-specific prerequisites and build flags, consult the appropriate doc/build-<your-OS>.md (e.g., doc/build-linux.md, doc/build-osx.md, etc.).

3. Download the fuzz input corpora
  After a successful build, fetch the pre-collected input corpora from the Bitcoin Core qa-assets repository - https://github.com/bitcoin-core/qa-assets.

4. Install the mutation testing framework
  Ensure you have Python 3 installed, then run:
  ```bash
  pip install mutation-core
  ```
  This installs the mutation-core tool that drives the mutation generation and execution across the fuzz targets.

5. Run the experiments
  Every muts* folder contains the mutants for a matching file. For example, the folder `muts-feefrac-h` contains the mutants for the file src/util/feefrac.h. Then, to reproduce our results you can the mutation analysis using mutation-core by running the fuzz target with the inputs from the qa-assets. E.g.:

  ```bash
  mutation-core analyze -f="muts-feefrac-h" -c="cmake --build build_fuzz && FUZZ=feefrac_div_fallback qa-assets/fuzz_corpora/feefrac_div_fallback -runs=1"
  ```

  Another example - for the folder `muts-coinselection-cpp`:

  ```bash
  mutation-core analyze -f="muts-coinselection-cpp" -c="cmake --build build_fuzz && FUZZ=coinselection_bnb path-to-qa-assets/fuzz_corpora/coinselection_bnb -runs=1"
  ```

  It means:

  ```bash
  mutation-core analyze -f="folder-with-mutants" -c="cmake --build build_fuzz && FUZZ=name_of_fuzz_target qa-assets/fuzz_corpora/name_of_fuzz_target -runs=1"
  ```

  The name of every fuzz target used in our experiments is presented in Table 1 from the paper.

With these steps, you should be able to reproduce all measurements presented in the paper.
