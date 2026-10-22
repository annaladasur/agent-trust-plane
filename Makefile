.DEFAULT_GOAL := help
PYTHON ?= python3
OPA ?= opa
.PHONY: help demo test test-policies test-python recount lab-up lab-g0 lab-down
help:
	@echo 'make demo          Evaluate local policy examples (OPA required)'
	@echo 'make test          Run Rego and offline Python tests'
	@echo 'make recount       Recount saved historical records, without inference'
	@echo 'make lab-up        Explicitly opted-in experimental kind lab; see docs/LAB.md'

demo:
	$(PYTHON) scripts/policy_demo.py --opa $(OPA)
test: test-policies test-python
test-policies:
	$(OPA) test policies/ -v
test-python:
	$(PYTHON) -m unittest discover -s tests -v
recount:
	$(PYTHON) scripts/recount.py
lab-up:
	@test "$(ATP_UNSAFE_LAB)" = 1 || (echo 'Read docs/KNOWN-LIMITATIONS.md; use ATP_UNSAFE_LAB=1 only in a disposable local lab.'; exit 1)
	$(MAKE) -f cluster/Makefile.lab up
lab-g0:
	@test "$(ATP_UNSAFE_LAB)" = 1 || (echo 'Disposable lab only; read docs/LAB.md.'; exit 1)
	$(MAKE) -f cluster/Makefile.lab g0
lab-down:
	kind delete cluster --name atp
