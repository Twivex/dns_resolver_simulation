package dns_resolver_simulation;

import org.xbill.DNS.Record;

public class QueryEntry {
  public Record question;
  public double arrival;
  public int cacheResponse;
}