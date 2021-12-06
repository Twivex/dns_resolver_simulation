package dns_resolver_simulation;

import java.io.IOException;

public class Statistics {

  LatencyStatistics cacheHitStatistics;
  LatencyStatistics allStatistics;
  LatencyStatistics correctRTStatistics;
  private int cacheHitCounter;
  private int cacheMissCounter;
  private int falsePositiveCounter;
  private int wrongResponsesCounter;
  private int nsecCacheCounter;
  private int nsec3CacheCounter;
  private int wildcardCacheCounter;
  private int optOutInSavingCounter;
  private int optOutInLookupCounter;
  private int intQueryCounter;
  private int intResponseCounter;
  private int extQueryCounter;
  private int extResponseCounter;
  private int extWildcardResponseCounter;
  private FileWriter counterFile;
  private int truncatedRRSIGCounter;

  public Statistics(Logger logger, int timeRange, int timeSpread) {

    // initialze statistic variables
    this.latencyCategories = new int[(timeRange / timeSpread) + 1];
    this.cacheHitCounter = 0;
    this.cacheMissCounter = 0;
    this.falsePositiveCounter = 0;
    this.wrongResponsesCounter = 0;
    this.nsecCacheCounter = 0;
    this.nsec3CacheCounter = 0;
    this.wildcardCacheCounter = 0;
    this.optOutInSavingCounter = 0;
    this.optOutInLookupCounter = 0;
    this.intQueryCounter = 0;
    this.extQueryCounter = 0;
    this.intResponseCounter = 0;
    this.extResponseCounter = 0;
    this.extWildcardResponseCounter = 0;
    this.truncatedRRSIGCounter = 0;

    this.counterFile = logger.getFileWriter("counter");

    this.cacheHitStatistics = new LatencyStatistics(logger, Constants.CACHE_HIT_STATISTICS, timeRange, timeSpread);
    this.allStatistics = new LatencyStatistics(logger, Constants.ALL_STATISTICS, timeRange, timeSpread);
    this.correctRTStatistics = new LatencyStatistics(logger, Constants.CORRECT_RESPONSE_TYPE, timeRange, timeSpread);

  }

  public void countCacheHit() {
    this.cacheHitCounter++;
  }

  public void countCacheMiss() {
    this.cacheMissCounter++;
  }

  public void countFalsePositive() {
    this.falsePositiveCounter++;
  }

  public void countWrongResponse() {
    this.wrongResponsesCounter++;
  }

  public void countNsecCache() {
    this.nsecCacheCounter++;
  }

  public void countNsec3Cache() {
    this.nsec3CacheCounter++;
  }

  public void countWildcardCache() {
    this.wildcardCacheCounter++;
  }

  public void countOptOutInLookup() {
    this.optOutInLookupCounter++;
  }

  public void countOptOutInSaving() {
    this.optOutInSavingCounter++;
  }

  public void countInternalQuery() {
    this.intQueryCounter++;
  }

  public void countExternalQuery() {
    this.extQueryCounter++;
  }

  public void countExternalResponse() {
    this.extResponseCounter++;
  }

  public void countInternalResponse() {
    this.intResponseCounter++;
  }

  public void countExternalWildcardResponse() {
    this.extWildcardResponseCounter++;
  }

  public void countTruncatedRRSIG() {
    this.truncatedRRSIGCounter++;
  }

  public void saveLatencyStatistic(String name, double current, double past, boolean countHitExtra) {
    LatencyStatistics chosenStatistics = null;

    switch(name) {
      case Constants.CACHE_HIT_STATISTICS:
        chosenStatistics = this.cacheHitStatistics;
        break;

      case Constants.ALL_STATISTICS:
        chosenStatistics = this.allStatistics;
        break;

      case Constants.CORRECT_RESPONSE_TYPE:
        chosenStatistics = this.correctRTStatistics;
        break;

      default:
        // do nothing
    }
    if (chosenStatistics != null) {
      chosenStatistics.add(current, past, countHitExtra);
    }
  }

  public void writeAll() {
    writeCounter();
    this.cacheHitStatistics.writeCSVFile();
    this.allStatistics.writeCSVFile();
    this.correctRTStatistics.writeCSVFile();
  }

  public void writeCounter() {
    this.counterFile.add("--- Counter ---");
    this.counterFile.add("Number of queries INT -> R: " + this.intQueryCounter);
    this.counterFile.add("Number of queries R -> EXT: " + this.extQueryCounter);
    this.counterFile.add("Number of responses EXT -> R: " + this.extResponseCounter);
    this.counterFile.add("Number of responses R -> INT: " + this.intResponseCounter);
    this.counterFile.add("Number of responses with wildcards EXT -> R: " + this.extWildcardResponseCounter);
    this.counterFile.add("Cache hit: " + this.cacheHitCounter);
    this.counterFile.add("Cache miss: " + this.cacheMissCounter);
    this.counterFile.add("False positives: " + this.falsePositiveCounter);
    this.counterFile.add("Wrong response from cache: " + this.wrongResponsesCounter);
    this.counterFile.add("NSEC records added to cach: " + this.nsecCacheCounter);
    this.counterFile.add("NSEC3 records added to cache: " + this.nsec3CacheCounter);
    this.counterFile.add("Wildcard records added to cache: " + this.wildcardCacheCounter);
    this.counterFile.add("NSEC3 opt-out in savings: " + this.optOutInSavingCounter);
    this.counterFile.add("NSEC3 op-out in lookups: " + this.optOutInLookupCounter);
    this.counterFile.add("Truncated RRSIGs: " + this.truncatedRRSIGCounter);

    try {
      this.counterFile.write();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}