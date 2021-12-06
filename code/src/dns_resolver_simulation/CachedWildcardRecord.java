package dns_resolver_simulation;

import org.xbill.DNS.Record;

public class CachedWildcardRecord extends CachedRecord {

  public CachedWildcardRecord(Record record, double arrival) {
    super(record, arrival);
  }

  @Override
  public double getTTL() {
    return Long.valueOf(this.record.getTTL()).doubleValue();
  }
}