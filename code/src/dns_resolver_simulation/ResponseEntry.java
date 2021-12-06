package dns_resolver_simulation;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.RRSIGRecord;

public class ResponseEntry {
  private HashMap<String, CachedNegativeRecord> recordsList;
  
  public ResponseEntry() {
    recordsList = new HashMap<String, CachedNegativeRecord>();
  }
  
  public void add(NSECRecord record, RRSIGRecord sigRecord, double arrival, double ttl) {
    CachedNegativeRecord cachedNsecRecord = new CachedNSECRecord(record, sigRecord, arrival, ttl);
    String key = record.getName().canonicalize().toString();
    recordsList.put(key, cachedNsecRecord);
  }
    
  public void add(NSEC3Record record, RRSIGRecord sigRecord, double arrival, double ttl) {
    CachedNegativeRecord cachedNsec3Record = new CachedNSEC3Record(record, sigRecord, arrival, ttl);
    String key = record.getName().canonicalize().toString();
    recordsList.put(key, cachedNsec3Record);
  }

  public boolean isEmpty() {
    return this.recordsList.isEmpty();
  }

  public Iterator<Map.Entry<String, CachedNegativeRecord>> getIterator() {
    return this.recordsList.entrySet().iterator();
  }

  public Collection<CachedNegativeRecord> getRecords() {
    return this.recordsList.values();
  }
}
