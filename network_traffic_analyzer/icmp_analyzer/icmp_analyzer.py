from scapy.all import ICMP
import numpy as np
import pandas as pd
from network_traffic_analyzer.packet_analyzer import PacketAnalyzer

# ICMP layer analyzer
class IcmpAnalyzer(PacketAnalyzer):
    # extract ICMP layer
    # override
    def _extractData(self, pkt, packetInfo):
        packetInfo = super()._extractData(pkt, packetInfo)

        if ICMP in pkt:
            icmp = pkt[ICMP]
            packetInfo["icmp_type"] = icmp.type # ICMP type, 8 = echo request, 0 = echo reply
            packetInfo["icmp_code"] = icmp.code # ICMP code, type subcode
            packetInfo["icmp_checksum"] = icmp.chksum # ICMP checksum
            packetInfo["icmp_id"] = icmp.id # ICMP identifier
            packetInfo["icmp_seq"] = icmp.seq # ICMP sequence number

        return packetInfo
        
    # return ICMP IDs list in ascending order (no duplicates)
    def getIcmpIdsList(self):
        return sorted(self.packetsDataFrame["icmp_id"].dropna().astype(int).unique())

    # return RTT statistics based on ICMP request/reply
    # override
    def getRttStats(self):
        requests = self.packetsDataFrame[self.packetsDataFrame["icmp_type"] == 8]
        replies = self.packetsDataFrame[self.packetsDataFrame["icmp_type"] == 0]

        if requests.empty or replies.empty:
            return pd.DataFrame()
        
        
        
        rttsList = []
        for packetIndex in range(1, len(self.icmpPackets)):
            timeDifference = (self.icmpPackets.iloc[packetIndex]['timestamp'] - self.icmpPackets.iloc[packetIndex-1]['timestamp']).total_seconds() * 1000
            rttsList.append(timeDifference)

        rttMean = np.mean(rttsList) if rttsList else 0
        rttStd = np.std(rttsList) if rttsList else 0
        rttMaximum = np.max(rttsList) if rttsList else 0
        rttMinimum = np.min(rttsList) if rttsList else 0
        standardError = rttStd / np.sqrt(len(rttsList)) if len(rttsList) > 0 else 0
        coefficientVariation = (rttStd / rttMean) * 100 if rttMean > 0 else 0

        return {
            "rtts": rttsList,
            "mean": rttMean,
            "std": rttStd,
            "max": rttMaximum,
            "min": rttMinimum,
            "error": standardError,
            "cv": coefficientVariation
        }
    
    # retorna estatísticas de intervalo de chegada entre pacotes ICMP
    # override
    def getIntervalStats(self):
        if len(self.icmpPackets) < 2:
            return {"intervals": [], "mean": 0, "std": 0, "max": 0, "min": 0, "error": 0, "cv": 0}

        intervalsList = []
        for packetIndex in range(1, len(self.icmpPackets)):
            timeDifference = (self.icmpPackets.iloc[packetIndex]['timestamp'] - self.icmpPackets.iloc[packetIndex-1]['timestamp']).total_seconds() * 1000
            intervalsList.append(timeDifference)

        intervalMean = np.mean(intervalsList) if intervalsList else 0
        intervalStd = np.std(intervalsList) if intervalsList else 0
        intervalMaximum = np.max(intervalsList) if intervalsList else 0
        intervalMinimum = np.min(intervalsList) if intervalsList else 0
        standardError = intervalStd / np.sqrt(len(intervalsList)) if len(intervalsList) > 0 else 0
        coefficientVariation = (intervalStd / intervalMean) * 100 if intervalMean > 0 else 0

        return {
            "intervals": intervalsList,
            "mean": intervalMean,
            "std": intervalStd,
            "max": intervalMaximum,
            "min": intervalMinimum,
            "error": standardError,
            "cv": coefficientVariation
        }

    # retorna estatísticas de perda de pacotes ICMP
    # override
    def getLossStats(self):
        totalPackets = len(self.icmpPackets)
        
        if totalPackets == 0:
            return {"sent": 0, "received": 0, "lost": 0, "lossRate": 0}

        sentPackets = totalPackets // 2 if totalPackets > 0 else 0
        receivedPackets = totalPackets - sentPackets
        lostPackets = sentPackets - receivedPackets if sentPackets > receivedPackets else 0
        lossRate = (lostPackets * 100) / sentPackets if sentPackets > 0 else 0

        return {
            "sent": sentPackets,
            "received": receivedPackets,
            "lost": lostPackets,
            "lossRate": lossRate
        }

    # imprime métricas ICMP
    # override
    def printGeneralMetrics(self):
        id = self.getId()
        totalPackets = self.getTotalPackets()
        totalBytes = self.getTotalBytes()
        layers = self.getLayers().get("layers")
        throughput = self.getThroughput()

        return super().printGeneralMetrics(id, totalPackets, totalBytes, layers, throughput)

    # override
    def printRttMetrics(self):
        layer = "ICMP"
        stats = self.getRttStats()
        mean = stats.get("mean")
        std = stats.get("std")
        maximum = stats.get("max")
        minimum = stats.get("min")
        error = stats.get("error")
        cv = stats.get("cv")

        return super().printRttMetrics(layer, mean, std, maximum, minimum, error, cv)

    # override
    def printIntervalMetrics(self):
        layer = "ICMP"
        stats = self.getIntervalStats()
        mean = stats.get("mean")
        std = stats.get("std")
        maximum = stats.get("max")
        minimum = stats.get("min")
        error = stats.get("error")
        cv = stats.get("cv")

        return super().printIntervalMetrics(layer, mean, std, maximum, minimum, error, cv)

    # override
    def printLossMetrics(self):
        layer = "ICMP"
        stats = self.getLossStats()
        sent = stats.get("sent")
        received = stats.get("received")
        lost = stats.get("lost")
        lossRate = stats.get("lossRate")

        return super().printLossMetrics(layer, sent, received, lost, lossRate)

    # plotagem de gráficos ICMP
    # override
    def plotLayersGraph(self, path):
        id = self.getId()
        layers = self.getLayers().get("layers")
        nLayers = self.getLayers().get("nLayers")
        title = None
        xLabel = "Protocol layers"
        yLabel = "Amount of packets"
        return super().plotLayersGraph(path, id, layers, nLayers, title, xLabel, yLabel)

    # override
    def plotRttGraph(self, path):
        id = self.getId()
        xAxis = self.getIcmpIdsList()
        rtts = self.getRttStats().get("rtts")
        title = None
        xLabel = "ICMP packet sequence"
        yLabel = "RTT (ms)"
        return super().plotRttGraph(path, id, xAxis, rtts, title, xLabel, yLabel)

    # override
    def plotIntervalGraph(self, path):
        id = self.getId()
        xAxis = self.getIcmpIdsList()
        intervals = self.getIntervalStats().get("intervals")
        title = None
        xLabel = "ICMP packet sequence"
        yLabel = "Interval between packets (ms)"
        return super().plotIntervalGraph(path, id, xAxis[1:], intervals, title, xLabel, yLabel)

    # override
    def plotRttHistogram(self, path):
        id = self.getId()
        rtts = self.getRttStats().get("rtts")
        title = None
        xLabel = "RTT (ms)"
        yLabel = "Frequency"
        return super().plotRttHistogram(path, id, rtts, title, xLabel, yLabel)

    # override
    def plotIntervalHistogram(self, path):
        id = self.getId()
        intervals = self.getIntervalStats().get("intervals")
        title = None
        xLabel = "Interval (ms)"
        yLabel = "Frequency"
        return super().plotIntervalHistogram(path, id, intervals, title, xLabel, yLabel)

    # override
    def plotLossGraph(self, path):
        id = self.getId()
        stats = self.getLossStats()
        lossStats = [stats.get("sent"), stats.get("received"), stats.get("lost")]
        title = None
        xLabel = "Sent, Received, Lost"
        yLabel = "Packet Count"
        return super().plotLossGraph(path, id, lossStats, title, xLabel, yLabel)

    # override
    def plotLossRateGraph(self, path):
        id = self.getId()
        lossRate = self.getLossStats().get("lossRate")
        return super().plotLossRateGraph(path, id, lossRate)