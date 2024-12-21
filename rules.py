def large_data(flow):
    return flow.bidirectional_bytes > 1024

def port_80(flow):
    return flow.dst_port == 80

def high_packets(flow):
    return flow.bidirectional_packets > 16