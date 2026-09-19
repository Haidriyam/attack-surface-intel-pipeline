name: Recon Intelligence DevSecOps CI

on: [push, pull_request]

jobs:
  audit-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Static Security Analysis (Bandit SAST)
        run: |
          bandit -r pipeline/ -ll

      - name: PEP8 Linting & Style Enforcement
        run: |
          flake8 pipeline/ tests/ --count --ignore=W292 --max-line-length=100 --statistics

      - name: Run Intelligence & Reporting Test Suite
        run: |
          PYTHONPATH=. pytest tests/ -v

      - name: Build Hardened Container
        run: |
          docker build -t attack-surface-intel-pipeline:latest .