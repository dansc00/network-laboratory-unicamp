from scapy.all import IP
import pandas as pd
import numpy as np
from network_traffic_analyzer.packet_analyzer import PacketAnalyzer

# analisador de camada IP
class IpAnalyzer(PacketAnalyzer):

    def __init__(self, captureId=None, packetsMargin=None, pcapPath=None):
        super().__init__(captureId, packetsMargin, pcapPath)
        self.ipPackets = self._extractIpPackets()
        self.sourceAddresses = self._extractSourceAddresses()
        self.destinationAddresses = self._extractDestinationAddresses()
        
    def _extractIpPackets(self):
        return self.getPackets().reset_index(drop=True)
        
    def _extractSourceAddresses(self):
        return set()
        
    def _extractDestinationAddresses(self):
        return set()

    # retorna lista de IDs IP em ordem crescente (sem duplicatas)
    def getIpIdsList(self):
        if len(self.ipPackets) > 0:
            return sorted(list(range(len(self.ipPackets))))
        return []

    # retorna estatísticas de RTT baseado em pacotes IP
    # override
    def getRttStats(self):
        if len(self.ipPackets) < 2:
            return {"rtts": [], "mean": 0, "std": 0, "max": 0, "min": 0, "error": 0, "cv": 0}
        
        rttsList = []
        for packetIndex in range(1, len(self.ipPackets)):
            timeDifference = (self.ipPackets.iloc[packetIndex]['timestamp'] - self.ipPackets.iloc[packetIndex-1]['timestamp']).total_seconds() * 1000
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
    
    # retorna estatísticas de intervalo de chegada entre pacotes IP
    # override
    def getIntervalStats(self):
        if len(self.ipPackets) < 2:
            return {"intervals": [], "mean": 0, "std": 0, "max": 0, "min": 0, "error": 0, "cv": 0}

        intervalsList = []
        for packetIndex in range(1, len(self.ipPackets)):
            timeDifference = (self.ipPackets.iloc[packetIndex]['timestamp'] - self.ipPackets.iloc[packetIndex-1]['timestamp']).total_seconds() * 1000
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

    # retorna estatísticas de perda de pacotes IP
    # override
    def getLossStats(self):
        totalPackets = len(self.ipPackets)
        
        if totalPackets == 0:
            return {"sent": 0, "received": 0, "lost": 0, "lossRate": 0}

        sentPackets = totalPackets
        receivedPackets = totalPackets
        lostPackets = 0
        lossRate = 0

        return {
            "sent": sentPackets,
            "received": receivedPackets,
            "lost": lostPackets,
            "lossRate": lossRate
        }

    # imprime métricas IP
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
        layer = "IP"
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
        layer = "IP"
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
        layer = "IP"
        stats = self.getLossStats()
        sent = stats.get("sent")
        received = stats.get("received")
        lost = stats.get("lost")
        lossRate = stats.get("lossRate")

        return super().printLossMetrics(layer, sent, received, lost, lossRate)

    # plotagem de gráficos IP
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
        xAxis = self.getIpIdsList()
        rtts = self.getRttStats().get("rtts")
        title = None
        xLabel = "IP packet sequence"
        yLabel = "RTT (ms)"
        return super().plotRttGraph(path, id, xAxis, rtts, title, xLabel, yLabel)

    # override
    def plotIntervalGraph(self, path):
        id = self.getId()
        xAxis = self.getIpIdsList()
        intervals = self.getIntervalStats().get("intervals")
        title = None
        xLabel = "IP packet sequence"
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