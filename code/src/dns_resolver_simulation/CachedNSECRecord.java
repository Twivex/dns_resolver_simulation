package dns_resolver_simulation;

import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;

public class CachedNSECRecord extends CachedNegativeRecord {
  private EnhancedNSECRecord record;

  public CachedNSECRecord(NSECRecord record, RRSIGRecord sigRecord, double arrival, double ttl) {
    super(record, sigRecord, arrival, ttl);
    this.record = new EnhancedNSECRecord(record);
  }

  @Override
  public int[] getTypes() {
    return this.record.getTypes();
  }

  @Override
  public boolean matches(Name needle) {
    return this.record.matches(needle);
  }

  @Override
  public boolean inbetween(Name needle) {
    return this.record.inBetween(needle);
  }

  @Override
  public Name getClosestEncloser(Name needle) {
    return this.record.getClosestEncloser(needle);
  }

}