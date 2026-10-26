from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay

PLOTS_DIR = Path(__file__).resolve().parent.parent / "plots"

fields = [
    'src_port',
    'dst_port',
    'protocol',
    'bidirectional_packets',
    'bidirectional_bytes',
    'bidirectional_duration_ms'
]


def plot_flow_bytes_distribution(flow_analysis, output_path=PLOTS_DIR / "flow_analysis.png"):
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    flow_totals = [
        (int(flow['total_bytes']), f'{flow["source_ip"]} ->\n{flow["destination_ip"]}')
        for flow in flow_analysis
    ]
    total_bytes = sum(bytes_count for bytes_count, _ in flow_totals)
    threshold = total_bytes // 100
    other_bytes = sum(bytes_count for bytes_count, _ in flow_totals if bytes_count < threshold)
    major_flows = [flow for flow in flow_totals if flow[0] >= threshold]

    values = [bytes_count for bytes_count, _ in major_flows] + [other_bytes]
    labels = [label for _, label in major_flows] + ['other']

    fig, ax = plt.subplots(figsize=(7, 7))
    ax.pie(values, labels=labels, autopct=lambda pct: f'{int(round(pct * total_bytes))}B')
    ax.set_title("Flow Analysis")
    fig.savefig(output_path)
    plt.close(fig)


def plot_rule_counts(rule_analysis, output_path=PLOTS_DIR / "rule_analysis.png"):
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    rule_names = list(rule_analysis.keys())
    counts = list(rule_analysis.values())

    fig, ax = plt.subplots(figsize=(7, 7))
    ax.bar(rule_names, counts)
    ax.set_title("Rule Analysis")
    ax.tick_params(axis='x', rotation=45)
    for label in ax.get_xticklabels():
        label.set_horizontalalignment('right')
    fig.savefig(output_path)
    plt.close(fig)


def plot_ml_distribution(ml_analysis, output_path=PLOTS_DIR / "ml_analysis.png"):
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    labels = list(ml_analysis.keys())
    counts = list(ml_analysis.values())

    fig, ax = plt.subplots(figsize=(7, 7))
    ax.pie(counts, labels=labels)
    ax.set_title("ML Analysis")
    fig.savefig(output_path)
    plt.close(fig)


def plot_live_rule_breaks(rule_breaks, output_path=PLOTS_DIR / "rule_analysis.png"):
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 7))
    for rule_name, timeline in rule_breaks.items():
        minutes = [float(minute) for minute in timeline.keys()]
        occurrences = list(timeline.values())
        ax.plot(minutes, occurrences, label=rule_name)
    ax.set_xlabel('Czas (min)')
    ax.set_ylabel('Wystąpienia')
    ax.legend()
    fig.savefig(output_path)
    plt.close(fig)


def normal_graphs(result):
    plot_flow_bytes_distribution(result['flow_analysis'])
    plot_rule_counts(result['rule_analysis'])
    if 'ml_analysis' in result:
        plot_ml_distribution(result['ml_analysis'])


def live_graphs(result):
    plot_live_rule_breaks(result['rule_breaks'])
    if 'ml_analysis' in result:
        plot_ml_distribution(result['ml_analysis'])


def plot_confusion_matrix(cm, labels, filename=PLOTS_DIR / "confusion_matrix.png"):
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots()
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(cmap="Blues", values_format="d", ax=ax)
    ax.set_title("Confusion Matrix")
    fig.savefig(filename, bbox_inches="tight")
    plt.close(fig)


def plot_feature_importance(model, filename=PLOTS_DIR / "feature_importance.png"):
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    importance = np.abs(model.coef_[0])
    feature_importance = pd.Series(importance, index=fields).sort_values(ascending=False)

    fig, ax = plt.subplots(figsize=(8, 6))
    feature_importance.plot(kind='bar', color='teal', ax=ax)
    ax.set_title("Feature Importance")
    ax.set_xlabel("Features")
    ax.set_ylabel("Absolute Weight")
    ax.tick_params(axis='x', rotation=45)
    for label in ax.get_xticklabels():
        label.set_horizontalalignment('right')
    fig.tight_layout()
    fig.savefig(filename, bbox_inches="tight")
    plt.close(fig)

