package dns_resolver_simulation;

import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;

public class CachedNSEC3Record extends CachedNegativeRecord {
  private EnhancedNSEC3Record record;

  public CachedNSEC3Record(NSEC3Record record, RRSIGRecord sigRecord, double arrival, double ttl) {
    super(record, sigRecord, arrival, ttl);
    this.record = new EnhancedNSEC3Record(record);
  }

  @Override
  public int[] getTypes() {
    return this.record.getTypes();
  }

  @Override
  public boolean inbetween(Name needle) {
    return this.record.inbetween(needle);
  }

  @Override
  public boolean matches(Name needle) {
    return this.record.matches(needle);
  }

  @Override
  public boolean hasOptOut() {
    return this.record.getFlags() == NSEC3Record.Flags.OPT_OUT;
  }

  @Override
  public Name getClosestEncloser(Name needle) {
    return this.record.getClosestEncloser(needle);
  }

}