from pathlib import Path
from os import walk
from os.path import join
from yaml import load, CLoader

RULES_DIR = Path(__file__).resolve().parent / "rules"


def large_data(flow):
    return flow.bidirectional_bytes > 1024


def port_80(flow):
    return flow.dst_port == 80


def high_packets(flow):
    return flow.bidirectional_packets > 16


def load_rules(rules_dir=RULES_DIR):
    directory, _, files = next(walk(rules_dir))
    result = []
    for file_name in sorted(files):
        with open(join(directory, file_name), 'r') as yaml_file:
            rule = load(yaml_file, Loader=CLoader)
            title = rule['title']
            selector = rule['detection']['condition']
            field, values = next(iter(rule['detection'][selector].items()))
            test = lambda flow, f=field, v=values: getattr(flow, f) in v
            test.__name__ = title
            result.append(test)
    return result


def get_all_rules(rules_dir=RULES_DIR):
    return [*load_rules(rules_dir), high_packets, port_80, large_data]

