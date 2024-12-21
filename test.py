import json
import time

from nfstream import NFStreamer
# from sklearn.ensemble import RandomForestClassifier
from rules import high_packets, port_80, large_data

protocols = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6'
}


def listen(interface):
    try:
        streamer = NFStreamer(source=interface, idle_timeout=5, active_timeout=40, promiscuous_mode=True)
    except:
        print('Błąd podczas nasłuchiwaniu na interfejsie')
        return
    start = time.time_ns()
    rules = [high_packets, port_80, large_data]
    breaks = [[] for _ in rules]
    n = 0
    try:
        for flow in streamer:
            print(flow.bidirectional_duration_ms)
            n += 1
            current = time.time_ns()
            for i, r in enumerate(rules):
                if r(flow):
                    hour = 5000 * (current - start) // (3600 * (10 ** 9))
                    while len(breaks[i]) <= hour:
                        breaks[i].append(0)
                    breaks[i][hour] +=1
                    print(f'Złamana zasada: {r.__name__}')
    except KeyboardInterrupt as e:
        print('stop')
    finally:
        print(breaks)



def analyze_pcap(file):
    try:
        streamer = NFStreamer(source=file)
    except:
        print('Błąd podczas ładowania pliku')
        return
    src_dst_stats = {}
    rules = [high_packets, port_80, large_data]
    rule_counts = [0 for _ in rules]
    lengths = []
    for flow in streamer:
        lengths.append(flow.bidirectional_duration_ms)
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
    result = {
        'flow_analysis': flow_analysis,
        'rule_analysis': rule_analysis
    }
    print(json.dumps(result, indent=4))
    print(sorted(lengths, reverse=True))


def main():
    # file = input('Wybierz plik do analizy:\n')
    # analyze_pcap(file)
    interface = input('Wybierz interfejs do analizy:\n')
    listen(interface)


if __name__ == '__main__':
    main()