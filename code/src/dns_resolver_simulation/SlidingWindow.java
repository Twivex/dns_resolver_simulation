package dns_resolver_simulation;

import java.util.HashMap;

import org.xbill.DNS.Record;

public class SlidingWindow {
  private HashMap<String, QueryEntry> storage;
  private DNSMessageUtilities messageUtils;
  private String currentKey;

  public SlidingWindow(DNSMessageUtilities messageUtils) {
    this.messageUtils = messageUtils;
    this.storage = new HashMap<String, QueryEntry>();
  }

  private String obtainKey(String ip, String port) {
    return ip + ":" + port + "#" + this.messageUtils.getID();
  }

  public void addEntry(int cacheResponse) throws RuntimeException {
    String key = getKey();
    Record question = this.messageUtils.getQuestion();
    QueryEntry check = this.storage.get(key);
    if (check != null && !check.question.getName().equals(question.getName())) {
      throw new RuntimeException("QueryEntry already exists");
    }
    QueryEntry queryEntry = new QueryEntry();
    queryEntry.question = question;
    queryEntry.arrival = this.messageUtils.getCurrentTime();
    queryEntry.cacheResponse = cacheResponse;

    this.storage.put(key, queryEntry);
  }

  public void setKey(String ip, String port) {
    this.currentKey = obtainKey(ip, port);
  }

  public String getKey() throws RuntimeException {
    if (this.currentKey.isEmpty()) throw new RuntimeException("Key of SlidingWindow not set");
    return this.currentKey;
  }

  public QueryEntry getEntry() throws RuntimeException {
    QueryEntry found = storage.get(getKey());
    if (found == null) {
      throw new RuntimeException("QueryEntry not found");
    }
    return found;
  }

  public void removeEntry() {
    this.storage.remove(getKey());
  }
}