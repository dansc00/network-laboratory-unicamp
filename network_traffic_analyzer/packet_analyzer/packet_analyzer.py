from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP
import pandas as pd
import numpy as np
from network_traffic_analyzer.report_printer import ReportPrinter
from network_traffic_analyzer.report_plotter import ReportPlotter
import sys

# PCAP capture analyzer
class PacketAnalyzer():
    def __init__(self, captureId=None, packetsMargin=None, pcapPath=None, parquetPath=None):
        self.captureId = captureId
        self.packetsMargin = packetsMargin
        self.pcapPath = pcapPath
        self.parquetPath = parquetPath
        
        try:
            # if parquet does not exist, call the converter
            if not self.parquetPath:                    
                self.__convertToParquet()

            self.packetsDataFrame = pd.read_parquet(self.parquetPath)
            self._applyMargin()

        except Exception as e:
            print(f"Error processing capture file: {e}")
            sys.exit(1)

    # convert pcap to parquet dataframe
    def __convertToParquet(self):
        packetsRecords = []
        packets = PcapReader(self.pcapPath)

        for pkt in packets:
            packetsRecords.append(self._extractData(pkt, {}))
        packets.close()

        df = pd.DataFrame(packetsRecords)
        df["formatted_timestamp"] = pd.to_datetime(df["timestamp"], unit="s") # formatted timestamp
        df.to_parquet(self.parquetPath, engine="pyarrow", compression="snappy", index=False)

    # extract default network layers
    def _extractData(self, pkt, packetInfo):        
        if Ether in pkt:
            ethernet = pkt[Ether]
            packetInfo["ether_src_mac"] = ethernet.src # MAC source address
            packetInfo["ether_dst_mac"] = ethernet.dst # MAC destination address
            packetInfo["ether_type"] = ethernet.type # network layer 
        
        if IP in pkt:
            ipv4 = pkt[IP]
            packetInfo["ipv4_version"] = ipv4.version # IP protocol version
            packetInfo["ipv4_ihl"] = ipv4.ihl # internet header length (number of 4 bytes block)
            packetInfo["ipv4_tos"] = ipv4.tos # type of service
            packetInfo["ipv4_len"] = ipv4.len # total length
            packetInfo["ipv4_id"] = ipv4.id 
            packetInfo["ipv4_flags"] = int(ipv4.flags) # fragmentation controller
            packetInfo["ipv4_frag"] = ipv4.frag # fragmentation offset (number of 8 bytes block)
            packetInfo["ipv4_ttl"] = ipv4.ttl # time to live
            packetInfo["ipv4_proto"] = ipv4.proto # next header (transport layer)
            packetInfo["ipv4_checksum"] = ipv4.chksum # header checksum
            packetInfo["ipv4_src"] = ipv4.src
            packetInfo["ipv4_dst"] = ipv4.dst
            packetInfo["ipv4_options"] = [opt.name for opt in ipv4.options] if ipv4.options else None # options list

        if IPv6 in pkt:
            ipv6 = pkt[IPv6]
            packetInfo["ipv6_version"] = ipv6.version # IP protocol version
            packetInfo["ipv6_tc"] = ipv6.tc # traffic class
            packetInfo["ipv6_fl"] = ipv6.fl # flow label
            packetInfo["ipv6_plen"] = ipv6.plen # payload length
            packetInfo["ipv6_nh"] = ipv6.nh # next header (transport layer)
            packetInfo["ipv6_hlim"] = ipv6.hlim # hop limit
            packetInfo["ipv6_src"] = ipv6.src
            packetInfo["ipv6_dst"] = ipv6.dst
        
        if TCP in pkt:
            tcp = pkt[TCP]
            packetInfo["tcp_sport"] = tcp.sport # source port
            packetInfo["tcp_dport"] = tcp.dport # destination port
            packetInfo["tcp_seq"] = tcp.seq # sequence number
            packetInfo["tcp_ack"] = tcp.ack # acknowledgment number
            packetInfo["tcp_dataofs"] = tcp.dataofs # data offset (header length in 4 bytes block)
            packetInfo["tcp_reserved"] = tcp.reserved # reserved bits
            packetInfo["tcp_flags"] = str(tcp.flags) # control flags
            packetInfo["tcp_window"] = tcp.window # window size
            packetInfo["tcp_checksum"] = tcp.chksum # checksum
            packetInfo["tcp_urgptr"] = tcp.urgptr # urgent pointer
            packetInfo["tcp_options"] = str(tcp.options) # raw options list

            # options parsing for common TCP options
            packetInfo["tcp_mss"] = None # maximum segment size
            packetInfo["tcp_wscale"] = None # window scale
            packetInfo["tcp_sack_permitted"] = False # sack permitted

            for opt in tcp.options:
                if isinstance(opt, tuple):
                    if opt[0] == "MSS":
                        packetInfo["tcp_mss"] = opt[1]
                    elif opt[0] == "WScale":
                        packetInfo["tcp_wscale"] = opt[1]
                    elif opt[0] == "SAckOK":
                        packetInfo["tcp_sack_permitted"] = True

        elif UDP in pkt:
            udp = pkt[UDP]
            packetInfo["udp_sport"] = udp.sport # source port
            packetInfo["udp_dport"] = udp.dport # destination port
            packetInfo["udp_len"] = udp.len # length
            packetInfo["udp_checksum"] = udp.chksum # checksum

        packetInfo["timestamp"] = float(pkt.time) # raw timestamp
        packetInfo["size"] = len(pkt) # packet size in bytes
        packetInfo["layers"] = [layer.__name__ for layer in pkt.layers()] # list of layers
        packetInfo["interface"] = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else None # interface name
        packetInfo["summary"] = pkt.summary() # packet summary
    
        return packetInfo
    
    # apply margin to avoid edge bias
    def _applyMargin(self):
        if self.packetsMargin != None and self.packetsMargin > 0:
            self.packetsDataFrame = self.packetsDataFrame.iloc[self.packetsMargin:-self.packetsMargin]
        
    # return specific packet by index
    def getPacket(self, packetIndex):
        return self.packetsDataFrame.iloc[packetIndex] if len(self.packetsDataFrame) > 0 else None
    
    # return timestamp in ms for specific packet by index
    def getTime(self, packetIndex):
        return self.packetsDataFrame.iloc[packetIndex]["timestamp"] * 1000
    
    # return formatted timestamp in ms for specific packet by index
    def getFormattedTime(self, packetIndex):
        return self.packetsDataFrame.iloc[packetIndex]["formatted_timestamp"]
    
    # return id
    def getId(self):
        return self.captureId
    
    # return total of captured packets
    def getTotalPackets(self):
        return len(self.packetsDataFrame)
    
    # return total of captured bytes
    def getTotalBytes(self):
        return self.packetsDataFrame["size"].sum() if self.getTotalPackets() > 0 else 0
    
    # return total capture time in ms
    def getTotalTime(self):
        if self.getTotalPackets() > 0:
            firstTime = self.packetsDataFrame.iloc[0]["timestamp"] * 1000
            lastTime = self.packetsDataFrame.iloc[-1]["timestamp"] * 1000
            return lastTime - firstTime
        return 0
    
    # return capture rate in packets per second
    def getCaptureRate(self):
        return self.getTotalPackets()/(self.getTotalTime()/1000) if self.getTotalTime() > 0 else 0

    # return the capture time difference in ms between two packets
    def getTimeDiff(self, packet1Index, packet2Index):
        return self.getTime(packet2Index) - self.getTime(packet1Index)
    
    # return throughput in Mbps
    def getThroughput(self):
        totalBits = self.getTotalBytes() * 8
        return (totalBits/(self.getTotalTime()/1000))/1000000 if self.getTotalTime() > 0 else 0
    
    # return layers list and layers count
    def getLayers(self):
        if self.getTotalPackets() == 0:
            return {
                "layers": [],
                "nLayers": 0
                }
        
        allLayers = self.packetsDataFrame["layers"].explode()
        layers = allLayers.value_counts()
        
        return {
                "layers": layers.index.tolist(),
                "nLayers": layers.values.tolist()
                }
    
    # return jitter statistics based on data variation: list of jitters, mean, standard deviation, max, min, standard error and coefficient of variation
    def getJitterStats(self, inputData):       
        if self.getTotalPackets() < 3:
            print("There is no way to measure jitter with less than three packets")
            return None
        
        jittersList = np.abs(np.diff(inputData)) if len(inputData) > 0 else []
        jitterMean = np.mean(jittersList) if len(jittersList) > 0 else 0
        jitterStd = np.std(jittersList) if len(jittersList) > 0 else 0
        jitterMax = np.max(jittersList) if len(jittersList) > 0 else 0
        jitterMin = np.min(jittersList) if len(jittersList) > 0 else 0
        standardError = jitterStd/np.sqrt(len(jittersList)) if len(jittersList) > 0 else 0
        coefficientVariation = (jitterStd/jitterMean)*100 if jitterMean > 0 else 0

        return {
                "jitters": jittersList,
                "mean": jitterMean,
                "std": jitterStd,
                "max": jitterMax,
                "min": jitterMin,
                "error": standardError,
                "cv": coefficientVariation
                }

    def getPacketByKey(self, key):
        pass
    
    def getRttStats(self):
        pass
    
    def getIntervalStats(self):
        pass
    
    def getLossStats(self):
        pass

    # print general metrics
    def printGeneralMetrics(self, id, totalPackets, totalBytes, layers, throughput):
        ReportPrinter.printGeneralMetrics(id, totalPackets, totalBytes, layers, throughput)

    # print RTT metrics
    def printRttMetrics(self, layer, mean, std, max, min, error, cv):       
        ReportPrinter.printRttMetrics(layer, mean, std, max, min, error, cv)
    
    # print interval metrics
    def printIntervalMetrics(self, layer, mean, std, max, min, error, cv):
        ReportPrinter.printIntervalMetrics(layer, mean, std, max, min, error, cv)

    # print RTT jitter metrics
    def printRttJitterMetrics(self, layer, mean, std, max, min, error, cv):
        ReportPrinter.printRttJitterMetrics(layer, mean, std, max, min, error, cv)

    # print interval jitter metrics
    def printIntervalJitterMetrics(self, layer, mean, std, max, min, error, cv):
        ReportPrinter.printIntervalJitterMetrics(layer, mean, std, max, min, error, cv)
    
    # print loss metrics
    def printLossMetrics(self, layer, sent, received, lost, lossRate):
        ReportPrinter.printLossMetrics(layer, sent, received, lost, lossRate)

    # plot layers bar graph
    def plotLayersGraph(self, path, id, layers, nLayers, title=None, xLabel=None, yLabel=None, legendFlag=True, horizontal=False):
        ReportPlotter.plotLayersGraph(path, id, layers, nLayers, title, xLabel, yLabel, legendFlag, horizontal)

    # plot RTT graph
    def plotRttGraph(self, path, id, xAxis, rtts, title=None, xLabel=None, yLabel=None):
        ReportPlotter.plotRttGraph(path, id, xAxis, rtts, title, xLabel, yLabel)

    # plot interval graph
    def plotIntervalGraph(self, path, id, xAxis, intervals, title=None, xLabel=None, yLabel=None):
        ReportPlotter.plotIntervalGraph(path, id, xAxis, intervals, title, xLabel, yLabel)

    # plot jitter graph based on RTT
    def plotRttJitterGraph(self, path, id, xAxis, jitters, title=None, xLabel=None, yLabel=None):
        ReportPlotter.plotRttJitterGraph(path, id, xAxis, jitters, title, xLabel, yLabel)

    # plot jitter graph based on arrival time interval
    def plotIntervalJitterGraph(self, path, id, xAxis, jitters, title=None, xLabel=None, yLabel=None):       
        ReportPlotter.plotIntervalJitterGraph(path, id, xAxis, jitters, title, xLabel, yLabel)

    # plot RTT histogram
    def plotRttHistogram(self, path, id, rtts, title=None, xLabel=None, yLabel=None):        
        ReportPlotter.plotRttHistogram(path, id, rtts, title, xLabel, yLabel)
    
    # plot interval histogram
    def plotIntervalHistogram(self, path, id, intervals, title=None, xLabel=None, yLabel=None):       
        ReportPlotter.plotIntervalHistogram(path, id, intervals, title, xLabel, yLabel)

    # plot jitter histogram based on RTT
    def plotRttJitterHistogram(self, path, id, jitters, title=None, xLabel=None, yLabel=None):
        ReportPlotter.plotRttJitterHistogram(path, id, jitters, title, xLabel, yLabel)

    # plot jitter histogram based on arrival time interval
    def plotIntervalJitterHistogram(self, path, id, jitters, title=None, xLabel=None, yLabel=None):
        ReportPlotter.plotIntervalJitterHistogram(path, id, jitters, title, xLabel, yLabel)
    
    # plot loss graph
    def plotLossGraph(self, path, id, lossStats, title=None, xLabel=None, yLabel=None):       
        ReportPlotter.plotLossGraph(path, id, lossStats, title, xLabel, yLabel)

    # plot loss rate graph
    def plotLossRateGraph(self, path, id, lossRate):       
        ReportPlotter.plotLossRateGraph(path, id, lossRate)



