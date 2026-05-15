from network_traffic_analyzer.graph_plotter import GraphPlotter

class ReportPlotter:
    @staticmethod
    def plotLayersGraph(path, id, layers, nLayers, title=None, xLabel=None, yLabel=None, legendFlag=True, horizontal=False):
        layersGraph = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel, legendFlag=legendFlag, legendPosition="right")
        layersGraph.plotBarGraph(layers, nLayers, plotLabel=layers, horizontal=horizontal)
        layersGraph.saveGraph(path+id+"-layers.png")

    @staticmethod
    def plotRttGraph(path, id, xAxis, rtts, title=None, xLabel=None, yLabel=None):
        rttGraph = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel)
        rttGraph.plotLineGraph(xAxis, rtts, color="blue", plotLabel="Round Trip Time", marker=None, autoScaleY=True)
        rttGraph.saveGraph(path+id+"-rtt.png")

    @staticmethod
    def plotIntervalGraph(path, id, xAxis, intervals, title=None, xLabel=None, yLabel=None):
        intervalGraph = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel)
        intervalGraph.plotLineGraph(xAxis, intervals, color="yellow", plotLabel="Packets arrival time interval", marker=None)
        intervalGraph.saveGraph(path+id+"-interval.png")

    @staticmethod
    def plotRttJitterGraph(path, id, xAxis, jitters, title=None, xLabel=None, yLabel=None):
        rttJitterGraph = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel)
        rttJitterGraph.plotLineGraph(xAxis, jitters, color="red", plotLabel="RTT based Jitter", marker=None)
        rttJitterGraph.saveGraph(path+id+"-rtt-jitter.png")

    @staticmethod
    def plotIntervalJitterGraph(path, id, xAxis, jitters, title=None, xLabel=None, yLabel=None):       
        intervalJitterGraph = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel)
        intervalJitterGraph.plotLineGraph(xAxis, jitters, color="orange", plotLabel="Arrival time interval based Jitter", marker=None)
        intervalJitterGraph.saveGraph(path+id+"-interval-jitter.png")

    @staticmethod
    def plotRttHistogram(path, id, rtts, title=None, xLabel=None, yLabel=None):        
        rttHistogram = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel, legendFlag=False)
        rttHistogram.plotHistogram(rtts, color="blue")
        rttHistogram.saveGraph(path+id+"-rtt-histogram.png")
    
    @staticmethod
    def plotIntervalHistogram(path, id, intervals, title=None, xLabel=None, yLabel=None):       
        intervalHistogram = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel, legendFlag=False)
        intervalHistogram.plotHistogram(intervals, color="yellow")
        intervalHistogram.saveGraph(path+id+"-interval-histogram.png")

    @staticmethod
    def plotRttJitterHistogram(path, id, jitters, title=None, xLabel=None, yLabel=None):
        jitterHistogram = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel, legendFlag=False)
        jitterHistogram.plotHistogram(jitters, color="red")
        jitterHistogram.saveGraph(path+id+"-rtt-jitter-histogram.png")

    @staticmethod
    def plotIntervalJitterHistogram(path, id, jitters, title=None, xLabel=None, yLabel=None):
        jitterHistogram = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel, legendFlag=False)
        jitterHistogram.plotHistogram(jitters, color="orange")
        jitterHistogram.saveGraph(path+id+"-interval-jitter-histogram.png")
    
    @staticmethod
    def plotLossGraph(path, id, lossStats, title=None, xLabel=None, yLabel=None):       
        lossGraph = GraphPlotter(title=title, xLabel=xLabel, yLabel=yLabel, legendPosition="right")
        lossGraph.plotBarGraph(["sent", "received", "lost"], lossStats, ["gray", "green", "red"], ["Sent Packets", "Received Packets", "Lost Packets"])
        lossGraph.saveGraph(path+id+"-loss.png")

    @staticmethod
    def plotLossRateGraph(path, id, lossRate):       
        lossRateGraph = GraphPlotter()
        lossRateGraph.plotPizzaGraph(["received packets", "lost packets"], [100-lossRate, lossRate], ["green", "red"])
        lossRateGraph.saveGraph(path+id+"-loss-rate.png")