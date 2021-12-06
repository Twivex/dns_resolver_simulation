package dns_resolver_simulation;

import java.io.IOException;

public class LatencyStatistics {

  private int latencySpread;
  private double latencyTimeSpread;
  private double latencyTimeRange;
  private int[] latencyCategories;
  private FileWriter latencyFile;

  public LatencyStatistics(Logger logger, String name, int timeRange, int timeSpread) {
    this.latencyFile = logger.getFileWriter(name + "-latency", "csv");

    this.latencySpread = timeSpread;

    // latencyRange and latencySpread in ms
    this.latencyTimeRange = timeRange * Constants.MILLI_SECOND;
    this.latencyTimeSpread = timeSpread * Constants.MILLI_SECOND;

    this.latencyCategories = new int[(timeRange / timeSpread) + 1];
  }

  public void add(double current, double past, boolean countHitExtra) {
    if (countHitExtra) {
      latencyCategories[0]++;
    } else {
      double latency = current - past;

      if (latency >= 0) {
        if (latency < this.latencyTimeRange) {
          int index = (int) (latency / this.latencyTimeSpread);
          this.latencyCategories[index]++;
        } else {
          this.latencyCategories[this.latencyCategories.length - 1]++;
        }
      }
    }
  }

  
  public void writeCSVFile() {
    this.latencyFile.add("latency;count");
    for (int time = 0, i = 0; i < this.latencyCategories.length; time += this.latencySpread, i++) {
      int latencyCount = this.latencyCategories[i];
      this.latencyFile.add(time + ";" + latencyCount);
    }

    try {
      this.latencyFile.write();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}