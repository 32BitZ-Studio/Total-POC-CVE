###############################################################################
# General configuration
###############################################################################
PROJECT        ?= tmux
FUZZER         ?= cmd-fuzzer
OSS_FUZZ_DIR   ?= forks/oss-fuzz

# Path to the submission scripts for Part 1
SUBMISSION_DIR = submission/part_1
RUN_W_SCRIPT   = $(SUBMISSION_DIR)/run_w_corpus.sh
RUN_WO_SCRIPT  = $(SUBMISSION_DIR)/run_wo_corpus.sh

# Declare utility targets
.PHONY: prepare prepare_image prepare_fuzzers prepare_fuzzers_coverage \
        prepare_coverage clean coverage diff \
        run_w_corpus run_wo_corpus full_w_corpus full_wo_corpus

###############################################################################
# Build OSS-Fuzz image and fuzzers
###############################################################################
prepare_image:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_image $(PROJECT) --pull

prepare_fuzzers:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_fuzzers $(PROJECT)

# Build fuzzers with coverage sanitizer
prepare_fuzzers_coverage:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_fuzzers --sanitizer coverage $(PROJECT)

# Combined targets for easy setup
prepare: clean prepare_image prepare_fuzzers
prepare_coverage: clean prepare_image prepare_fuzzers_coverage

###############################################################################
# Run targets using submission scripts
###############################################################################
# Run fuzzing with initial seed corpus
run_w_corpus:
	@bash $(RUN_W_SCRIPT)

# Run fuzzing without any seed corpus
run_wo_corpus:
	@bash $(RUN_WO_SCRIPT)

###############################################################################
# Coverage report generation
###############################################################################
# Override CORPUS from the command line if needed:
#   make coverage CORPUS=build/out/work-corpus
CORPUS ?= $(OSS_FUZZ_DIR)/work-corpus
coverage:
	@python3 $(OSS_FUZZ_DIR)/infra/helper.py coverage $(PROJECT) \
	    --corpus-dir ../../$(CORPUS) --fuzz-target $(FUZZER)

###############################################################################
# Convenience composite targets
###############################################################################
# Build, run with seeds, then generate coverage
full_w_corpus: prepare_coverage run_w_corpus coverage
# Build, run without seeds, then generate coverage
full_wo_corpus: prepare_coverage run_wo_corpus coverage

###############################################################################
# Utility targets
###############################################################################
clean:
	@docker stop $$(docker ps -q) 2>/dev/null || true
