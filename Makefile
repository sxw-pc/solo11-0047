PYTHON ?= python
CONFIG ?= configs/pipeline.yaml
export PYTHONPATH := src

.PHONY: test run serve diff trace validate fixtures

test:
	$(PYTHON) -m pytest

run:
	$(PYTHON) -m slowquery_autopsy run --config $(CONFIG)

serve:
	$(PYTHON) -m slowquery_autopsy serve --config $(CONFIG)

diff:
	$(PYTHON) -m slowquery_autopsy diff --config $(CONFIG)

trace:
	$(PYTHON) -m slowquery_autopsy trace --config $(CONFIG)

validate:
	$(PYTHON) -m slowquery_autopsy validate --config $(CONFIG)

fixtures:
	$(PYTHON) scripts/gen_fixtures.py
