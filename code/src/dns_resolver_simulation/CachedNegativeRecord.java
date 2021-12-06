package dns_resolver_simulation;

import java.util.Arrays;

import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Record;

public abstract class CachedNegativeRecord extends CachedRecord {
  protected RRSIGRecord sigRecord;
  protected double ttl;

  public CachedNegativeRecord(Record record, RRSIGRecord sigRecord, double arrival, double ttl) {
    super(record, arrival);
    this.sigRecord = sigRecord;
    this.ttl = ttl;
  }

  @Override
  public double getTTL() {
    return this.ttl;
  }

  public RRSIGRecord getSigRecord() {
    return this.sigRecord;
  }

  public boolean containsType(int type) {
    return Arrays.stream(getTypes()).anyMatch(i -> i == type);
  }

  public boolean hasOptOut() {
    return false;
  }

  public abstract Name getClosestEncloser(Name questionName);

  public abstract int[] getTypes();
  
  public abstract boolean matches(Name needle);

  public abstract boolean inbetween(Name needle);

}