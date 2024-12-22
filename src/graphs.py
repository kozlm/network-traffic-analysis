import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay

fields = [
    'src_port',
    'dst_port',
    'protocol',
    'bidirectional_packets',
    'bidirectional_bytes',
    'bidirectional_duration_ms'
]

def normal_graphs(result):
    # bytes pie plot
    data = [(int(d['total_bytes']), f'{d["source_ip"]} ->\n{d["destination_ip"]}') for d in result['flow_analysis']]
    s = sum(x[0] for x in data)
    limit = s // 100
    other = sum(x[0] for x in data if x[0] < limit)
    good = [d for d in data if d[0] >= limit]
    x = [d[0] for d in good]
    l = [d[1] for d in good]
    x.append(other)
    l.append('other')
    plt.figure(figsize=(7, 7))
    plt.pie(x, labels=l, autopct=lambda a: f'{int(round(a * s))}B')
    plt.title("Flow Analysis")
    plt.savefig("../plots/flow_analysis.png")
    plt.close()

    # rule bar plot
    plt.figure(figsize=(7, 7))
    items = list(i for i in result['rule_analysis'].items())
    c = [i[0] for i in items]
    v = [i[1] for i in items]
    plt.bar(c, v)
    plt.title("Rule Analysis")
    plt.xticks(rotation=45, ha='right')
    plt.savefig("../plots/rule_analysis.png")
    plt.close()

    if 'ml_analysis' not in result:
        return

    # ml plot
    items = list(i for i in result['ml_analysis'].items())
    c = [i[0] for i in items]
    v = [i[1] for i in items]
    plt.pie(v, labels=c)
    plt.title("ML Analysis")
    plt.savefig("../plots/ml_analysis.png")
    plt.close()


def live_graphs(result):
    plt.figure(figsize=(7, 7))
    for n, v in result['rule_breaks'].items():
        items = [i for i in v.items()]
        x = [float(i[0]) for i in items]
        y = [i[1] for i in items]
        plt.plot(x, y, label=n)
    plt.xlabel('Czas (min)')
    plt.ylabel('Wystąpienia')
    plt.legend()
    plt.show()
    if 'ml_analysis' not in result:
        return
    items = list(i for i in result['ml_analysis'].items())
    c = [i[0] for i in items]
    v = [i[1] for i in items]
    plt.pie(v, labels=c)
    plt.show()


def plot_confusion_matrix(cm, labels, filename="../plots/confusion_matrix.png"):
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(cmap="Blues", values_format="d")
    plt.title("Confusion Matrix")
    plt.savefig(filename, bbox_inches="tight")
    plt.close()

def plot_feature_importance(model):
    importance = np.abs(model.coef_[0])  # Get absolute values of the weights
    feature_importance = pd.Series(importance, index=fields).sort_values(ascending=False)

    feature_importance.plot(kind='bar', figsize=(8, 6), color='teal')
    plt.title("Feature Importance")
    plt.xlabel("Features")
    plt.ylabel("Absolute Weight")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig("../plots/feature_importance.png", bbox_inches="tight")
    plt.close()