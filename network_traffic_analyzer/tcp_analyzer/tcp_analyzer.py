from scapy.all import TCP
import pandas as pd
import numpy as np
from network_traffic_analyzer.packet_analyzer import PacketAnalyzer

# analisador de camada TCP
class TcpAnalyzer(PacketAnalyzer):

    def __init__(self, captureId=None, packetsMargin=None, pcapPath=None):
        super().__init__(captureId, packetsMargin, pcapPath)
        self.tcpPackets = self._extractTcpPackets()
        
    def _extractTcpPackets(self):
        return self.getPackets()[self.getPackets()['type'] == 'TCP'].reset_index(drop=True)

    # retorna lista de números de sequência TCP em ordem crescente (sem duplicatas)
    def getTcpSeqsList(self):
        if len(self.tcpPackets) > 0:
            return sorted(list(range(len(self.tcpPackets))))
        return []

    # retorna estatísticas de RTT baseado em pacotes TCP consecutivos
    # override
    def getRttStats(self):
        if len(self.tcpPackets) < 2:
            return {"rtts": [], "mean": 0, "std": 0, "max": 0, "min": 0, "error": 0, "cv": 0}
        
        rttsList = []
        for packetIndex in range(1, len(self.tcpPackets)):
            timeDifference = (self.tcpPackets.iloc[packetIndex]['timestamp'] - self.tcpPackets.iloc[packetIndex-1]['timestamp']).total_seconds() * 1000
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
    
    # retorna estatísticas de intervalo de chegada entre pacotes TCP
    # override
    def getIntervalStats(self):
        if len(self.tcpPackets) < 2:
            return {"intervals": [], "mean": 0, "std": 0, "max": 0, "min": 0, "error": 0, "cv": 0}

        intervalsList = []
        for packetIndex in range(1, len(self.tcpPackets)):
            timeDifference = (self.tcpPackets.iloc[packetIndex]['timestamp'] - self.tcpPackets.iloc[packetIndex-1]['timestamp']).total_seconds() * 1000
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

    # retorna estatísticas de perda/retransmissão de pacotes TCP
    # override
    def getLossStats(self):
        totalPackets = len(self.tcpPackets)
        
        if totalPackets == 0:
            return {"totalPackets": 0, "uniquePackets": 0, "retransmissions": 0, "lossRate": 0}

        uniquePackets = totalPackets
        retransmissionsCount = 0
        lossRate = 0

        return {
            "totalPackets": totalPackets,
            "uniquePackets": uniquePackets,
            "retransmissions": retransmissionsCount,
            "lossRate": lossRate
        }

    # imprime métricas TCP
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
        layer = "TCP"
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
        layer = "TCP"
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
        layer = "TCP"
        stats = self.getLossStats()
        total = stats.get("totalPackets")
        unique = stats.get("uniquePackets")
        retrans = stats.get("retransmissions")
        lossRate = stats.get("lossRate")

        return super().printLossMetrics(layer, total, unique, retrans, lossRate)

    # plotagem de gráficos TCP
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
        xAxis = self.getTcpSeqsList()
        rtts = self.getRttStats().get("rtts")
        title = None
        xLabel = "TCP sequence number"
        yLabel = "RTT (ms)"
        return super().plotRttGraph(path, id, xAxis, rtts, title, xLabel, yLabel)

    # override
    def plotIntervalGraph(self, path):
        id = self.getId()
        xAxis = self.getTcpSeqsList()
        intervals = self.getIntervalStats().get("intervals")
        title = None
        xLabel = "TCP sequence number"
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
        lossStats = [stats.get("totalPackets"), stats.get("uniquePackets"), stats.get("retransmissions")]
        title = None
        xLabel = "Total, Unique, Retrans"
        yLabel = "Packet Count"
        return super().plotLossGraph(path, id, lossStats, title, xLabel, yLabel)

    # override
    def plotLossRateGraph(self, path):
        id = self.getId()
        lossRate = self.getLossStats().get("lossRate")
        return super().plotLossRateGraph(path, id, lossRate)
