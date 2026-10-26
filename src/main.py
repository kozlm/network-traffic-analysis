import json
import sys
import time
from pathlib import Path

import click
from nfstream import NFStreamer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.machine_learning_model import (
    create_and_train_model,
    read_model,
    select_fields,
    test_model,
    train_model,
)
from src.report import generate_live_report, generate_pcap_analysis_report
from src.rules import get_all_rules, high_packets, large_data, load_rules, port_80

REPORTS_DIR = PROJECT_ROOT / "reports"

protocols = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6'
}


def save_raw_report(result, output_path=REPORTS_DIR / "raw.json"):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=4), encoding="utf-8")


def build_flow_analysis(src_dst_stats):
    flow_analysis = [
        {
            'flow_count': count,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'total_bytes': total_bytes,
            'protocols': [protocols[proto] for proto in proto_set],
            'broken_rules': list(broken_rules),
        }
        for (src_ip, dst_ip), (count, total_bytes, proto_set, broken_rules) in src_dst_stats.items()
    ]
    return sorted(flow_analysis, key=lambda item: item['flow_count'], reverse=True)


def evaluate_pcap_stream(streamer, rules, model=None):
    src_dst_stats = {}
    rule_counts = [0 for _ in rules]
    ml_counts = {'malicious': 0, 'normal': 0}

    for flow in streamer:
        pair = (flow.src_ip, flow.dst_ip)
        broken_rules = set()
        for index, rule in enumerate(rules):
            if rule(flow):
                rule_counts[index] += 1
                broken_rules.add(rule.__name__)

        if pair in src_dst_stats:
            count, total_bytes, proto_set, existing_rules = src_dst_stats[pair]
            src_dst_stats[pair] = (
                count + 1,
                total_bytes + flow.bidirectional_bytes,
                proto_set | {flow.protocol},
                existing_rules | broken_rules,
            )
        else:
            src_dst_stats[pair] = (
                1,
                flow.bidirectional_bytes,
                {flow.protocol},
                broken_rules,
            )

        if model is not None:
            prediction = model.predict(select_fields(flow))[0]
            ml_counts[prediction] += 1

    result = {
        'flow_analysis': build_flow_analysis(src_dst_stats),
        'rule_analysis': {rule.__name__: count for rule, count in zip(rules, rule_counts)},
    }
    if model is not None:
        result['ml_analysis'] = ml_counts
    return result


def evaluate_live_stream(streamer, rules, model=None):
    start_ns = time.time_ns()
    breaks = {rule.__name__: {0: 0} for rule in rules}
    rule_counts = {rule.__name__: 0 for rule in rules}
    ml_counts = {'malicious': 0, 'normal': 0}

    try:
        for flow in streamer:
            current_ns = time.time_ns()
            for rule in rules:
                if rule(flow):
                    minute = (current_ns - start_ns) / (60 * (10 ** 9))
                    rule_counts[rule.__name__] += 1
                    breaks[rule.__name__][minute] = rule_counts[rule.__name__]
                    print(f'ALERT: broken rule - {rule.__name__}')
            if model is not None:
                prediction = model.predict(select_fields(flow))[0]
                ml_counts[prediction] += 1
    except KeyboardInterrupt:
        print('stop')

    result = {'rule_breaks': breaks}
    if model is not None:
        result['ml_analysis'] = ml_counts
    return result


def analyze_pcap(rules):
    file_name = click.prompt("Enter the path of pcap file", type=str)
    use_ml = click.confirm("ML analysis?")
    model = read_model() if use_ml else None
    click.echo(f"Analysing file: {file_name}, ML analysis: {'Yes' if use_ml else 'No'}")

    streamer = NFStreamer(source=file_name)
    result = evaluate_pcap_stream(streamer, rules, model=model)
    save_raw_report(result)
    generate_pcap_analysis_report(result)


def listen_on_interface(rules):
    interface_name = click.prompt("Enter the interface name", type=str)
    use_ml = click.confirm("ML analysis?")
    model = read_model() if use_ml else None
    click.echo(f"Listening on the interface: {interface_name}, ML analysis: {'Yes' if use_ml else 'No'}")

    try:
        streamer = NFStreamer(source=interface_name, idle_timeout=5, active_timeout=40, promiscuous_mode=True)
    except Exception:
        print('Error occured while listening on the interface')
        return

    result = evaluate_live_stream(streamer, rules, model=model)
    save_raw_report(result)
    generate_live_report(result)


def create_new_model():
    malicious_pcap = click.prompt("Enter the path of pcap file with malicious training data")
    normal_pcap = click.prompt("Enter the path of pcap file with normal training data")
    click.echo(f"Creating new model using files: {malicious_pcap}, {normal_pcap}")
    create_and_train_model(malicious_pcap, normal_pcap)


def train_current_model():
    malicious_pcap = click.prompt("Enter the path of pcap file with malicious training data")
    normal_pcap = click.prompt("Enter the path of pcap file with normal training data")
    click.echo(f"Training model using files: {malicious_pcap}, {normal_pcap}")
    train_model(malicious_pcap, normal_pcap)


def test_current_model():
    malicious_pcap = click.prompt("Enter the path of pcap file with malicious testing data")
    normal_pcap = click.prompt("Enter the path of pcap file with normal testing data")
    click.echo(f"Testing model using files: {malicious_pcap}, {normal_pcap}")
    print(test_model(malicious_pcap, normal_pcap))


def display_menu():
    click.echo("What do you want to do?")
    click.echo("1. Analyze pcap file")
    click.echo("2. Analyze network traffic on the interface")
    click.echo("3. Create new model")
    click.echo("4. Train current model")
    click.echo("5. Test your model")
    click.echo("6. Exit")


@click.command()
def main_menu():
    rules = get_all_rules()
    actions = {
        1: lambda: analyze_pcap(rules),
        2: lambda: listen_on_interface(rules),
        3: create_new_model,
        4: train_current_model,
        5: test_current_model,
    }

    while True:
        display_menu()
        choice = click.prompt("Choose one of the options", type=int)

        if choice == 6:
            click.echo("Bye!")
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            click.echo("Wrong input, try again.")


if __name__ == "__main__":
    main_menu()

