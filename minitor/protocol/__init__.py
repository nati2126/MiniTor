"""
The MiniTor wire protocol.

- cells: fixed-size link cells, relay messages, and payload encodings
- channel: a TCP link that carries cells for many circuits
- circuit: client-side circuits (building, sending, receiving)
- stream: TCP-like streams carried over a circuit, with flow control
"""
