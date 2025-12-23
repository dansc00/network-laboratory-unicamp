# Network Traffic Analyzer

A comprehensive Python library for analyzing network traffic from PCAP files. This library provides specialized analyzers for different network protocols including ICMP, TCP, and IP, along with graph plotting capabilities.

## Features

- **Multi-Protocol Support**: Specialized analyzers for ICMP, TCP, and IP protocols
- **Statistical Analysis**: RTT, jitter, packet loss, throughput, and interval metrics
- **Visualization**: Built-in graph plotting with matplotlib support
- **Flexible Architecture**: Extensible base classes for custom protocol analyzers
- **PCAP Processing**: Direct support for PCAP file analysis using Scapy

## Installation

### Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Requirements and Setup
```bash
pip install -r requirements.txt
pip install -e .
```

## Quick Start

### Basic Usage

```python
from network_traffic_analyzer import IcmpAnalyzer, TcpAnalyzer, PacketAnalyzer

# Analyze ICMP traffic
icmp_analyzer = IcmpAnalyzer(id="ping_test", path="capture.pcap")
icmp_analyzer.printGeneralMetrics()
icmp_analyzer.printRttMetrics()
icmp_analyzer.plotRttGraph("output/")

# Analyze TCP traffic  
tcp_analyzer = TcpAnalyzer(id="tcp_session", path="tcp_capture.pcap")
tcp_analyzer.printGeneralMetrics()
tcp_analyzer.printRttMetrics()
tcp_analyzer.plotThroughputGraph("output/")

# General packet analysis
analyzer = PacketAnalyzer(id="general", path="mixed_traffic.pcap")
analyzer.printGeneralMetrics()
analyzer.plotLayersGraph("output/")
```

### Graph Plotting

```python
from network_traffic_analyzer.graph_plotter import GraphPlotter, Color

# Create custom graphs
plotter = GraphPlotter(
    title="Network Latency Over Time",
    xLabel="Time (s)", 
    yLabel="Latency (ms)"
)

plotter.plotLineGraph(time_data, latency_data, 
                     color=Color.BLUE, 
                     plotLabel="Ping RTT")
plotter.saveGraph("latency_graph.png")
```

## Available Analyzers

### PacketAnalyzer (Base Class)
- General packet statistics
- Layer analysis
- Throughput calculation
- Time-based metrics

### IcmpAnalyzer
- RTT analysis for ping packets
- Packet loss calculation
- Jitter measurements
- Interval analysis between ICMP requests

### TcpAnalyzer  
- TCP connection analysis
- RTT measurements for TCP sessions
- Retransmission detection
- Connection state tracking

### IpAnalyzer
- IP-level packet analysis
- Source/destination tracking
- Fragmentation analysis

## Graph Types Supported

- **Line Graphs**: Time series data, RTT plots, throughput
- **Bar Charts**: Protocol distribution, packet counts
- **Histograms**: RTT distribution, packet size analysis
- **Pie Charts**: Protocol ratios, loss percentages

## Metrics Available

- **RTT Statistics**: Mean, std deviation, min/max, jitter
- **Throughput**: Bits per second calculations
- **Packet Loss**: Loss rates and retransmission analysis  
- **Intervals**: Inter-arrival time analysis
- **Protocol Distribution**: Layer-wise packet counts


