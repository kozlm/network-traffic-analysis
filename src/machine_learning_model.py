import pickle

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from nfstream import NFStreamer
from sklearn.linear_model import SGDClassifier
from src.report import generate_testing_report

fields = [
    'src_port',
    'dst_port',
    'protocol',
    'bidirectional_packets',
    'bidirectional_bytes',
    'bidirectional_duration_ms'
]


def create_and_train_model(malicious_pcap, normal_pcap):
    model = SGDClassifier(alpha=0.01, max_iter=1000, random_state=42)
    x,y = get_merged_dataset(malicious_pcap, normal_pcap)
    model.fit(x, y)
    plot_feature_importance(model)
    save_model(model)


def train_model(malicious_pcap, normal_pcap):
    model = read_model()
    x,y = get_merged_dataset(malicious_pcap, normal_pcap)
    model.partial_fit(x, y)
    save_model(model)

def test_model(malicious_pcap, normal_pcap):
    model = read_model()
    x,y = get_merged_dataset(malicious_pcap, normal_pcap)
    predicted = model.predict(x)
    return generate_testing_report(y,predicted)

def get_merged_dataset(malicious_pcap, normal_pcap):
    malicious_data = create_dataframe(malicious_pcap)
    malicious_data['class_label'] = 'malicious'
    normal_data = create_dataframe(normal_pcap)
    normal_data['class_label'] = 'normal'
    testing_data = pd.concat([malicious_data, normal_data])
    x = testing_data.drop(columns=['class_label'])
    y = testing_data['class_label']
    return x, y

def plot_feature_importance(model):
    importance = np.abs(model.coef_[0])  # Get absolute values of the weights
    feature_importance = pd.Series(importance, index=fields).sort_values(ascending=False)

    # Plot feature importance
    feature_importance.plot(kind='bar', figsize=(8, 6), color='teal')
    plt.title("Feature Importance")
    plt.xlabel("Features")
    plt.ylabel("Absolute Weight")
    plt.tight_layout()
    plt.show()

def select_fields(flow):
    return pd.DataFrame({f: [getattr(flow, f)] for f in fields})

def create_dataframe(pcap_file):
    nfstreamer = NFStreamer(source=pcap_file)
    df = nfstreamer.to_pandas()
    return df[fields]

def save_model(model):
    with open("model.pkl", "wb") as file:
        pickle.dump(model, file)

def read_model():
    with open("model.pkl", "rb") as file:
        return pickle.load(file)