import json
import time

import click
from nfstream import NFStreamer
from yaml import load, CLoader
from os import walk
from os.path import join, isfile

from graphs import normal_graphs, live_graphs
from machine_learning_model import train_model, test_model, create_and_train_model, read_model, select_fields
from rules import high_packets, port_80, large_data
from src.machine_learning_model import plot_feature_importance
from src.report import generate_pcap_analysis_report

protocols = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6'
}


def load_rules():
    d, _, files = next(walk('rules'))
    result = []
    for f in files:
        with open(join(d, f), 'r') as y:
            rule = load(y, Loader=CLoader)
            title = rule['title']
            selector = rule['detection']['condition']
            field, values = next(iter(rule['detection'][selector].items()))
            test = lambda flow: getattr(flow, field) in values
            test.__name__ = title
            result.append(test)
    return result


def analyze_pcap(rules):
    file_name = click.prompt("Enter the path of pcap file", type=str)
    use_ml = click.confirm("ML analysis?")
    model = read_model() if use_ml else None
    click.echo(f"Analysing file: {file_name}, ML analysis: {'Yes' if use_ml else 'No'}")
    streamer = NFStreamer(source=file_name)
    src_dst_stats = {}
    rule_counts = [0 for _ in rules]
    e_counts = {'malicious': 0, 'normal': 0}
    for flow in streamer:
        d = flow.src_ip, flow.dst_ip
        broken_rules = set()
        for i, r in enumerate(rules):
            if r(flow):
                rule_counts[i] += 1
                broken_rules.add(r.__name__)
        if d in src_dst_stats:
            count, total, p, b = src_dst_stats[d]
            src_dst_stats[d] = count + 1, total + flow.bidirectional_bytes, p | {flow.protocol}, b | broken_rules
        else:
            src_dst_stats[d] = 1, flow.bidirectional_bytes, {flow.protocol}, broken_rules
        if use_ml:
            e_counts[model.predict(select_fields(flow))[0]] += 1
    flow_analysis = [{
        'flow_count': c,
        'source_ip': sp,
        'destination_ip': dp,
        'total_bytes': t,
        'protocols': [protocols[p] for p in ps],
        'broken_rules': list(br),
    } for (sp, dp), (c, t, ps, br) in src_dst_stats.items()]
    flow_analysis = sorted(flow_analysis, key=lambda c: c['flow_count'], reverse=True)
    rule_analysis = {r.__name__: c for r, c in zip(rules, rule_counts)}
    if use_ml:
        result = {
            'flow_analysis': flow_analysis,
            'rule_analysis': rule_analysis,
            use_ml and 'ml_analysis': e_counts
        }
    else:
        result = {
            'flow_analysis': flow_analysis,
            'rule_analysis': rule_analysis
        }
    print(json.dumps(result, indent=4))
    generate_pcap_analysis_report(result)



def listen_on_interface(rules):
    interface_name = click.prompt("Enter the interface name", type=str)
    use_ml = click.confirm("ML analysis?")
    model = read_model() if use_ml else None
    click.echo(f"Listening on the interface: {interface_name}, ML analysis: {'Yes' if use_ml else 'No'}")
    try:
        streamer = NFStreamer(source=interface_name, idle_timeout=5, active_timeout=40, promiscuous_mode=True)
    except:
        print('Error occured while listening on the interface')
        return
    start = time.time_ns()
    breaks = {r.__name__: {0: 0} for r in rules}
    rule_counts = {r.__name__: 0 for r in rules}
    e_counts = {'malicious': 0, 'normal': 0}
    n = 0
    try:
        for flow in streamer:
            n += 1
            current = time.time_ns()
            for i, r in enumerate(rules):
                if r(flow):
                    minute = (current - start) / (60 * (10 ** 9))
                    rule_counts[r.__name__] += 1
                    breaks[r.__name__][minute] = rule_counts[r.__name__]
                    print(f'ALERT: broken rule - {r.__name__}')
            if use_ml:
                e_counts[model.predict(select_fields(flow))[0]] += 1
    except KeyboardInterrupt as e:
        print('stop')
    finally:
        if use_ml:
            result = {
                'rule_breaks': breaks,
                'ml_analysis': e_counts,
            }
        else:
            result = {
                'rule_breaks': breaks
            }
        print(a := json.dumps(result, indent=4))
        with open('tmp.json', 'w') as f:
            f.write(a)
        live_graphs(result)


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


@click.command()
def main_menu():
    rules = [*load_rules(), high_packets, port_80, large_data]
    while True:
        click.echo("What do you want to do?")
        click.echo("1. Analyze pcap file")
        click.echo("2. Analyze network traffic on the interface")
        click.echo("3. Create new model")
        click.echo("4. Train current model")
        click.echo("5. Test your model")
        click.echo("6. Exit")

        choice = click.prompt("Choose one of the options", type=int)

        if choice == 1:
            analyze_pcap(rules)
        elif choice == 2:
            listen_on_interface(rules)
        elif choice == 3:
            create_new_model()
        elif choice == 4:
            train_current_model()
        elif choice == 5:
            test_current_model()
        elif choice == 6:
            click.echo("Bye!")
            break
        else:
            click.echo("Wrong input, try again.")




if __name__ == "__main__":
    main_menu()
