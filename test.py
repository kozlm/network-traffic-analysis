from nfstream import NFStreamer
from sklearn.ensemble import RandomForestClassifier

protocols = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6'
}


def main():
    file = input('Wybierz plik do analizy:\n')
    try:
        streamer = NFStreamer(source=file)
    except:
        print('Błąd podczas ładowania pliku')
        return
    src_dst_stats = {}
    for flow in streamer:
        d = flow.src_ip, flow.dst_ip
        if d in src_dst_stats:
            count, total, p = src_dst_stats[d]
            src_dst_stats[d] = count + 1, total + flow.bidirectional_bytes, p | {flow.protocol}
        else:
            src_dst_stats[d] = 1, flow.bidirectional_bytes, {flow.protocol}
    c1 = [(c, f'{sp:>30} -> {dp:<30} bytes: {t:>8} protocols: {", ".join(protocols[p] for p in ps):>10}') for (sp, dp), (c, t, ps) in src_dst_stats.items()]
    c1 = sorted(c1, key=lambda c: c[0], reverse=True)
    for c, s in c1:
        print(f'{c:>6} {s}')
    model = RandomForestClassifier()


if __name__ == '__main__':
    main()