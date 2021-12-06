package dns_resolver_simulation;

import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

public abstract class CachedRecord {
  protected Record record;
  protected double arrival;

  public CachedRecord(Record record, double arrival) {
    this.record = record;
    this.arrival = arrival;
  }

  public Record getRecord() {
    return this.record;
  }

  public Name getName() {
    return this.record.getName();
  }

  public double getArrival() {
    return this.arrival;
  }
  
  public int getType() {
    return this.record.getType();
  }

  public abstract double getTTL();
}