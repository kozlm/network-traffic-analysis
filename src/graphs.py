import matplotlib.pyplot as plt


def normal_graphs(result):
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
    plt.show()
    plt.figure(figsize=(7, 7))
    items = list(i for i in result['rule_analysis'].items())
    c = [i[0] for i in items]
    v = [i[1] for i in items]
    plt.bar(c, v)
    plt.show()
    if 'ml_analysis' not in result:
        return
    items = list(i for i in result['ml_analysis'].items())
    c = [i[0] for i in items]
    v = [i[1] for i in items]
    plt.pie(v, labels=c)
    plt.show()


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
