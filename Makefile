provision:
	python3 -m pip install pytest --break-system-packages

test:
	python3 -m pytest tests/ -v
	python3 -m pytest tests/test_mutation_table.py tests/test_mutation_harness.py -v
	python3 generate_report.py
	python3 -m pipeline.harness --fixtures fixtures/public-fixtures.json --junit-out regression-results.xml --json-out harness-report.json

clean:
	rm -f regression-results.xml harness-report.json mutation-test-report.csv
