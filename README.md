# Network Traffic Analysis

Network Traffic Analysis is a command-line framework for inspecting network flows, detecting suspicious traffic patterns, and classifying network activity using rule-based and machine learning approaches. It processes both offline `.pcap` captures and live network interfaces using [NFStream](https://github.com/nfstream/nfstream), [scikit-learn](https://scikit-learn.org/), [Matplotlib](https://matplotlib.org/), [Folium](https://python-visualization.github.io/folium/), and [Jinja2](https://jinja.palletsprojects.com/).

The tool combines static flow rules (written in Python and Sigma-style YAML definitions) with an incremental `SGDClassifier` machine learning model. Analysis results are exported as raw JSON data alongside self-contained HTML reports containing flow statistics, rule violation summaries, evaluation metrics, charts, and IP geolocation maps.

## Functionality

### Traffic Analysis Modes

- **PCAP File Analysis** – parses offline packet capture files (`.pcap`), aggregates bidirectional flow statistics between source and destination IP pairs, evaluates detection rules, optionally classifies flows with the trained ML model, geolocates public IP addresses via `ip-api.com`, and generates a full HTML report (`reports/pcap_analysis_report.html`).
- **Live Interface Monitoring** – captures traffic in real time on a specified network interface in promiscuous mode, prints immediate console alerts (`ALERT: broken rule - <rule_name>`) whenever a flow violates a rule, tracks rule violations over time, and generates a live analysis HTML report (`reports/live_analysis_report.html`) upon termination (`Ctrl+C`).

### Rule-Based Detection

Every network flow is evaluated against two sets of rules:
1. **Built-in flow rules** defined in [`src/rules.py`](src/rules.py):
   - `high_packets` – triggers when bidirectional packet count exceeds `16`,
   - `port_80` – triggers on destination port `80`,
   - `large_data` – triggers when bidirectional volume exceeds `1024` bytes.
2. **Sigma YAML rules** loaded dynamically from [`src/rules/`](src/rules) (e.g., [`src/rules/rule.yaml`](src/rules/rule.yaml) for detecting cleartext protocol ports).

### Machine Learning Classification

The framework uses `scikit-learn`'s `SGDClassifier` trained on labeled malicious and normal PCAP datasets ([`src/machine_learning_model.py`](src/machine_learning_model.py)). Flows are represented by six numerical features:
- `src_port`, `dst_port`, `protocol`, `bidirectional_packets`, `bidirectional_bytes`, `bidirectional_duration_ms`.

The model is serialized to `model.pkl` and supports:
- **Creating a new model** (`fit`) and generating a feature importance chart (`plots/feature_importance.png`),
- **Incremental training** (`partial_fit`) on additional PCAP files,
- **Model evaluation** on test PCAP files, calculating Accuracy, True Positive Rate (TPR), False Positive Rate (FPR), and rendering a confusion matrix report (`reports/model_report.html`).

## Requirements

- **Python** == 3.11
- **libpcap** (required by `nfstream` for packet capture)
- Root privileges or `CAP_NET_RAW` capability (only required for live interface capture)

## Installation

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/kozlm/network-traffic-analysis.git
   cd network-traffic-analysis
   ```

2. Create and activate a virtual environment, then install the dependencies from [`requirements.txt`](requirements.txt):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

Start the interactive CLI from the project root directory:

```bash
python3 -m src.main
```

*(For live interface capture requiring elevated permissions, run `sudo python3 -m src.main`.)*

You will be presented with the interactive menu:

```text
What do you want to do?
1. Analyze pcap file
2. Analyze network traffic on the interface
3. Create new model
4. Train current model
5. Test your model
6. Exit
Choose one of the options:
```

### Menu Options

* `1. Analyze pcap file` – prompts for a path to a `.pcap` file and whether to run ML analysis (`y/N`). Saves raw output to `reports/raw.json` and generates `reports/pcap_analysis_report.html`.
* `2. Analyze network traffic on the interface` – prompts for a network interface name (e.g., `eth0`, `wlan0`, `lo`) and whether to enable ML classification. Press `Ctrl+C` to stop listening and generate `reports/live_analysis_report.html`.
* `3. Create new model` – prompts for paths to malicious and normal training `.pcap` files, trains a new `SGDClassifier`, saves `model.pkl`, and plots `plots/feature_importance.png`.
* `4. Train current model` – incrementally updates the existing `model.pkl` with new malicious and normal `.pcap` files using `partial_fit`.
* `5. Test your model` – evaluates `model.pkl` against malicious and normal testing `.pcap` files, prints the accuracy score, and generates `reports/model_report.html`.
* `6. Exit` – exits the application.

## Project Structure

### Directories and Files

* `src/` – application source code:
  * [`src/main.py`](src/main.py) – Click CLI entrypoint and stream evaluation functions
  * [`src/rules.py`](src/rules.py) – built-in flow rules and Sigma YAML rule loader
  * [`src/rules/`](src/rules) – Sigma-style YAML rule definitions (e.g., [`rule.yaml`](src/rules/rule.yaml))
  * [`src/machine_learning_model.py`](src/machine_learning_model.py) – `SGDClassifier` training, incremental learning, and evaluation
  * [`src/graphs.py`](src/graphs.py) – Matplotlib chart generation (`flow_analysis.png`, `rule_analysis.png`, `ml_analysis.png`, `confusion_matrix.png`, `feature_importance.png`)
  * [`src/maps.py`](src/maps.py) – IP geolocation lookup (`ip-api.com`) and interactive Folium HTML map generation
  * [`src/report.py`](src/report.py) – Jinja2 HTML report rendering with base64-embedded plots
  * [`src/templates/`](src/templates) – Jinja2 HTML templates for PCAP, live, and model evaluation reports
* `pcap/` – sample packet captures (`malicious.pcap`, `normal.pcap`)
* `plots/` – generated Matplotlib charts and map snapshots
* `reports/` – generated HTML reports and `raw.json` output

## Adding a custom Sigma rule

Additional Sigma rules can be placed in [`src/rules/`](src/rules) following the structure in [`src/rules/rule.yaml`](src/rules/rule.yaml):

```yaml
title: Cleartext Protocol Usage
id: e2b2fa0f-934f-46db-81df-a4505e5f05f5
status: stable
detection:
  selection:
    dst_port:
      - 8080
      - 80
      - 23
      - 50000
      - 1521
  condition: selection
level: medium
```

