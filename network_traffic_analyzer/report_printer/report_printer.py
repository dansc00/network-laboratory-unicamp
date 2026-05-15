import numpy as np

class ReportPrinter:
    @staticmethod
    def getDecimalPlaces(error):
        if error == 0:
            return 0
        
        places = np.floor(np.log10(np.abs(error)))
        return max(0, int(-places))

    @staticmethod
    def printGeneralMetrics(id, totalPackets, totalBytes, layers, throughput):
        print(f"Capture {id}")
        print(f"Total packets: {totalPackets}")
        print(f"Total bytes: {totalBytes} bytes")
        print(f"Layers: {layers}")
        print(f"Throughput: {throughput:.4f} Mbps\n")

    @staticmethod
    def printRttMetrics(layer, mean, std, max, min, error, cv):       
        places = ReportPrinter.getDecimalPlaces(error)
        print(f"Mean {layer} RTT: {mean:.{places}f} ms")
        print(f"{layer} RTT standard deviation: {std:.{places}f} ms")
        print(f"Maximum {layer} RTT: {max:.{places}f} ms")
        print(f"Minimum {layer} RTT: {min:.{places}f} ms")
        print(f"Standard error: {error:.{places}f} ms")
        print(f"Percentage of standard deviation from the mean: {cv:.2f}%\n")
    
    @staticmethod
    def printIntervalMetrics(layer, mean, std, max, min, error, cv):
        places = ReportPrinter.getDecimalPlaces(error)
        print(f"Mean {layer} packets arrival time interval: {mean:.{places}f} ms")
        print(f"Standard deviation of {layer} packets arrival time interval: {std:.{places}f} ms")
        print(f"Maximum {layer} packet arrival time interval: {max:.{places}f} ms")
        print(f"Minimum {layer} request packet arrival time Interval: {min:.{places}f} ms")
        print(f"Standard error: {error:.{places}f} ms")
        print(f"Percentage of standard deviation from the mean: {cv:.2f}%\n")

    @staticmethod
    def printRttJitterMetrics(layer, mean, std, max, min, error, cv):
        places = ReportPrinter.getDecimalPlaces(error)
        print(f"{layer} RTT based jitter mean: {mean:.{places}f} ms")
        print(f"{layer} RTT based jitter standard deviation: {std:.{places}f} ms")
        print(f"{layer} RTT based maximum jitter: {max:.{places}f} ms")
        print(f"{layer} RTT based minimum jitter: {min:.{places}f} ms")
        print(f"Standard error: {error:.{places}f} ms")
        print(f"Percentage of standard deviation from the mean: {cv:.2f}%\n")

    @staticmethod
    def printIntervalJitterMetrics(layer, mean, std, max, min, error, cv):
        places = ReportPrinter.getDecimalPlaces(error)
        print(f"{layer} arrival time interval based jitter mean: {mean:.{places}f} ms")
        print(f"{layer} arrival time interval based jitter standard deviation: {std:.{places}f} ms")
        print(f"{layer} arrival time interval based maximum jitter: {max:.{places}f} ms")
        print(f"{layer} arrival time interval based minimum jitter: {min:.{places}f} ms")
        print(f"Standard error: {error:.{places}f} ms")
        print(f"Percentage of standard deviation from the mean: {cv:.2f}%\n")
    
    @staticmethod
    def printLossMetrics(layer, sent, received, lost, lossRate):
        print(f"{layer} sent packets: {sent}")
        print(f"{layer} received packets: {received}")
        print(f"{layer} lost packets: {lost}")
        print(f"{layer} loss rate: {lossRate}%\n")
        print("-------------------------------------------------------------------")