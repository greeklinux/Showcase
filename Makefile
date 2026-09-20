# Standard library only. No install step, no virtualenv, nothing to set up.
.PHONY: test test-quiet check table mutate help

help:
	@echo "make test        run the full suite with one line per test"
	@echo "make test-quiet  run the full suite and print only the summary"
	@echo "make check       re-derive every published figure and fail on drift"
	@echo "make table       assert every module against every defensive technique"
	@echo "make mutate      break the code on purpose and watch the suite catch it"

test:
	python3 -m unittest discover -s tests -v

test-quiet:
	python3 -m unittest discover -s tests

check:
	python3 tests/check_claims.py

table:
	python3 tests/check_cross_module.py

mutate:
	python3 tests/mutation_harness.py
