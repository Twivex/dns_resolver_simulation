package dns_resolver_simulation;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class SimulationCache {
  private HashMap<String, ResponseEntry> cache;
  private HashMap<String, CachedWildcardRecord> wildcardCache;
  private DNSMessageUtilities messageUtils;
  private Statistics statistics;

  public SimulationCache(DNSMessageUtilities messageUtils, Statistics statistics) {
    this.messageUtils = messageUtils;
    this.statistics = statistics;
    this.cache = new HashMap<String, ResponseEntry>();
    this.wildcardCache = new HashMap<String, CachedWildcardRecord>();
  }

  /* initial call of recursive obtain function: obtains the key for saving ResponseEntry with NSEC records in the cache
   * @params NSECRecord  its name and next will be used
   * @return String      key obtained from name and next
   */
  private String obtainSavingKey(NSECRecord record) {
    Name name = record.getName().canonicalize();
    Name next = record.getNext().canonicalize();
    String equalSuffix = obtainEqualSuffix(name, next, 1);
    if (equalSuffix.isEmpty())
      return ".";

    return equalSuffix;
  }

  /* initial call of recursive obtain function: obtains the key for saving ResponseEntry with NSEC3 records in the cache
   * @params NSEC3Record        its name and next will be used
   * @throws RuntimeException   source: this.messageUtilities.getQuestion()
   * @return String             key obtained from name and next
   */
  private String obtainSavingKey(NSEC3Record record) throws RuntimeException {
    Name name = record.getName().canonicalize();
    Name questionName = this.messageUtils.getQuestion().getName().canonicalize();
    String equalSuffix = obtainEqualSuffix(name, questionName, 1);
    if (equalSuffix.isEmpty())
      return ".";
      
    return equalSuffix;
  }

  /* finds equal suffix (starting from right) of name and next and returns it (used as key for the cache)
   * @params Name, Name, int   name and next to get labels from, int for decreasing index
   * @return String            key
   */
  private String obtainEqualSuffix(Name name, Name next, int drawBack) {
    int nameIndex = name.labels() - drawBack;
    int nextIndex = next.labels() - drawBack;

    if (nameIndex < 0 || nextIndex < 0) return "";

    String nameLabel = name.getLabelString(nameIndex);

    if (nameIndex - 1 >= 0 && nextIndex - 1 >= 0) {
      String followingNameLabel = name.getLabelString(nameIndex - 1);
      String followingNextLabel = next.getLabelString(nextIndex - 1);
      if (followingNameLabel.equals(followingNextLabel)) {
        return obtainEqualSuffix(name, next, drawBack + 1) + "." + nameLabel;
      }
    }
    return nameLabel;
  }

  private String obtainWildcardKey(Record wildcard) {
    Name wildcardName = wildcard.getName();
    RRSIGRecord rrsig = this.messageUtils.getRRSIGRecord(wildcardName, Section.ANSWER, wildcard.getType());
    return "*." + RecordUtilities.getCustomLabelString(wildcardName, wildcardName.labels() - 1 - rrsig.getLabels());
  }

  /* adds all NSEC records in the current selected DNS message (-> DNSMessageUtilities) to the cache
   * @throws RuntimeException   source: obtainSavingKey(NSEC3Record)->this.messageUtilities.getQuestion()
   */
  public void add() throws RuntimeException {
    double arrival = this.messageUtils.getCurrentTime();
    // add NSEC Records to cache
    for (NSECRecord nsecRecord : this.messageUtils.getAllNSECRecords()) {
      String key = obtainSavingKey(nsecRecord);
      ResponseEntry foundResponseEntry = this.cache.get(key);
      double ttl = this.messageUtils.obtainNegativeTTL(nsecRecord.getTTL());
      RRSIGRecord sigRecord = this.messageUtils.getRRSIGRecord(nsecRecord.getName(), Section.AUTHORITY, nsecRecord.getType());

      // if cache entry exists, add record to its list otherwise create new entry
      if (foundResponseEntry != null) {
        foundResponseEntry.add(nsecRecord, sigRecord, arrival, ttl);
        this.statistics.countNsecCache();
      } else {
        ResponseEntry responseEntry = new ResponseEntry();
        responseEntry.add(nsecRecord, sigRecord, arrival, ttl);
        this.statistics.countNsecCache();
        this.cache.put(key, responseEntry);
      }
    }

    // add NSEC3 Records to cache
    for (NSEC3Record nsec3Record : this.messageUtils.getAllNSEC3Records()) {
      String key = obtainSavingKey(nsec3Record);
      ResponseEntry foundResponseEntry = this.cache.get(key);
      double ttl = this.messageUtils.obtainNegativeTTL(nsec3Record.getTTL());
      RRSIGRecord sigRecord = this.messageUtils.getRRSIGRecord(nsec3Record.getName(), Section.AUTHORITY, nsec3Record.getType());

      // if cache entry exists, add record to its list otherwise create new entry
      if (foundResponseEntry != null) {
        foundResponseEntry.add(nsec3Record, sigRecord, arrival, ttl);
        this.statistics.countNsec3Cache();
        if (nsec3Record.getFlags() == NSEC3Record.Flags.OPT_OUT)
          this.statistics.countOptOutInSaving();
      } else {
        ResponseEntry responseEntry = new ResponseEntry();
        responseEntry.add(nsec3Record, sigRecord, arrival, ttl);
        this.cache.put(key, responseEntry);
        this.statistics.countNsec3Cache();
        if (nsec3Record.getFlags() == NSEC3Record.Flags.OPT_OUT)
          this.statistics.countOptOutInSaving();
      }
    }

  }

  public void addWildcard() {
    for (Record wildcard : this.messageUtils.getWildcards()) {
      CachedWildcardRecord wildcardRecord = new CachedWildcardRecord(wildcard, this.messageUtils.getCurrentTime());
      this.wildcardCache.put(obtainWildcardKey(wildcard), wildcardRecord);
      this.statistics.countWildcardCache();
    }
  }

  /* search for a given name in the cache, remove the most left label after each iteration and redo lookup
   * @params Name                         name, which shall be used for the lookup
   * @return Map<String, ResponseEntry>   map of all found ResponseEntries with their corresponding key from the cache
   */
  public Map<String, ResponseEntry> resolve(Name name) {
    Map<String, ResponseEntry> response = new HashMap<String, ResponseEntry>();
    String key;
    ResponseEntry found;
    for (int position = 0; position < name.labels(); position ++) {
      key = RecordUtilities.getCustomLabelString(name, position);
      found = this.cache.get(key);

      if (found != null) response.put(key, found);
    }

    return response;
  }

  /* 1) resolve all ResponseEntries by the question's name
   * 2) iterate over entries and check that it exists and is not empty
   * 3) iterate over stored NSEC records and do their respective proof for denial of existence
   * @return boolean   true if question's name lays between of one NSEC Record's name and next, false otherwise
   */
  public int proof() throws RuntimeException, NameTooLongException {
    int result = Constants.NO_RESPONSE;
    Record question = this.messageUtils.getQuestion();
    Name questionName = question.getName().canonicalize();
    Map<String, ResponseEntry> resolvedResponseEntryList = resolve(questionName);
    
    ResponseEntry resolvedResponseEntry;
    Iterator<Map.Entry<String, CachedNegativeRecord>> iterator;
    Name closestEncloser, chopped, lastChopped, nextCloserName;

    CachedNegativeRecord record;
    RRSIGRecord sigRecord;

    // iterate over found entries in the cache
    for (Map.Entry<String, ResponseEntry> resolvedResponseEntryListEntry : resolvedResponseEntryList.entrySet()) {
      resolvedResponseEntry = resolvedResponseEntryListEntry.getValue();

      if (resolvedResponseEntry == null) 
        continue;

      if (resolvedResponseEntry.isEmpty()) {
        this.cache.remove(resolvedResponseEntryListEntry.getKey());
        continue;
      }

      iterator = resolvedResponseEntry.getIterator();

      // iterate over RR in the found entries
      while (iterator.hasNext() && result == Constants.NO_RESPONSE) {
        Map.Entry<String, CachedNegativeRecord> cachedNegativeRecordEntry = iterator.next();
        record = cachedNegativeRecordEntry.getValue();
        sigRecord = record.getSigRecord();

        // check TTL
        if (record.getArrival() + record.getTTL() <= this.messageUtils.getCurrentTime()) {
          iterator.remove();
          continue;
        }

        if (record.getType() == Type.NSEC) {
          // RULE 1: requested RR name matches NSEC RR name, but the requested type is not in the NSEC RR's type bit maps field
          if (record.matches(questionName) && sigRecord != null && questionName.labels() - 1 == sigRecord.getLabels()) {
            if (record.containsType(question.getType()))
              return Constants.NO_RESPONSE;
            else
              return Constants.NO_DATA_RESPONSE;
          }
          // RULE 2: requested RR name lays between NSEC RR name and next, additionaly wildcard proof is done
          else if (record.inbetween(questionName)) {

            // build wildcard name and retrieve wildcard record (exact match or covering)
            closestEncloser = record.getClosestEncloser(questionName);
            if (closestEncloser == null)
              return Constants.NAME_ERROR_RESPONSE;

            return wildcardProof(closestEncloser, question.getType());
          }
        } else if (record.getType() == Type.NSEC3) {
          // if opt-out is set, denial of existence cannot be proofed nor denied
          if (record.hasOptOut()) {
            this.statistics.countOptOutInLookup();
            continue;
          }

          // requested RR name matches NSEC3 RR name, but the requested type is not in the NSEC3 RR's type bit maps field
          if (record.matches(questionName) && sigRecord != null && questionName.labels() - 1 == sigRecord.getLabels()) {
            if (record.containsType(question.getType()))
              return Constants.NO_RESPONSE;
            else 
              return Constants.NO_DATA_RESPONSE;
          } else {
            // do closest encloser proof
            // PART 1: get the closest encloser -> needed to proof that requested name does not exist
            closestEncloser = record.getClosestEncloser(questionName);
            if (closestEncloser != null) {
              // PART 2: next closer name is covered by record -> closest encloser >is< closest match -> name does not exist
              chopped = questionName.relativize(closestEncloser);
              if (chopped.labels() == 0)  // is direct match
              return Constants.NO_RESPONSE;
              
              lastChopped = Name.fromConstantString(chopped.getLabelString(chopped.labels() - 1));
              nextCloserName = Name.concatenate(lastChopped, closestEncloser);
              
              if (covered(nextCloserName))  {
                // do wildcard proof
                result = wildcardProof(closestEncloser, question.getType());
              }
            }

          }
        }
      }
    }

    return result;
  }

  /* checks whether the given name of a question is covered by any record given in the cache
   * @params Name     name which shall be checked
   * @return boolean  true if one cached record returns true for its inbetween function, false otherwise
   */
  private boolean covered(Name name) {
    Map<String, ResponseEntry> resolvedResponseEntryList = resolve(name);

    boolean inbetween = false;

    // iterate over found entries in the cache
    for (ResponseEntry resolvedResponseEntry : resolvedResponseEntryList.values()) {
      if (resolvedResponseEntry == null || resolvedResponseEntry.isEmpty()) {
        continue;
      }

      // iterate over Resource Records in the found entry
      for (CachedNegativeRecord record : resolvedResponseEntry.getRecords()) {
        if (inbetween)
          break;
        
        if (record.getArrival() + record.getTTL() > this.messageUtils.getCurrentTime()) {
          inbetween = record.inbetween(name);
        }
      }
    }

    return inbetween;
  }

  // function for all response types that need a wildcard proof
  private int wildcardProof(Name closestEncloser, int questionType) throws NameTooLongException {
    Name wildcardName = Name.concatenate(Name.fromConstantString("*"), closestEncloser);
    CachedNegativeRecord wildcardRecord = getBelongingRecord(wildcardName);

    if (wildcardRecord != null) {
      if (wildcardRecord.inbetween(wildcardName)) {
        return Constants.NAME_ERROR_RESPONSE;                                             // NAME ERROR RESPONSE
      } else if (wildcardRecord.matches(wildcardName)) {
        if (wildcardRecord.containsType(questionType)) {
          if (wildcardIsCached(wildcardName, questionType)){                              // WILDCARD ANSWER RESPONSE
            return Constants.WILDCARD_ANSWER_RESPONSE;
          }
        } else {
          return Constants.WILDCARD_NO_DATA_RESPONSE;                                     // WILDCARD NO DATA RESPONSE
        }
      }
    } else {
      if (wildcardIsCached(wildcardName, questionType)) {                                 // WILDCARD ANSWER RESPONSE
        return Constants.WILDCARD_ANSWER_RESPONSE;
      }
    }

    return Constants.NO_RESPONSE;
  }


  // returns matching or covering NSEC/3 record to the given name
  private CachedNegativeRecord getBelongingRecord(Name name) {
    CachedNegativeRecord match = null;
    CachedNegativeRecord cover = null;
    Map<String, ResponseEntry> resolvedResponseEntryList = resolve(name);

    ResponseEntry resolvedResponseEntry;

    // iterate over found entries in the cache
    for (Map.Entry<String, ResponseEntry> resolvedResponseEntryListEntry : resolvedResponseEntryList.entrySet()) {
      resolvedResponseEntry = resolvedResponseEntryListEntry.getValue();

      if (resolvedResponseEntry == null || resolvedResponseEntry.isEmpty()) {
        continue;
      }

      // iterate over Resource Records in the found entry
      for (CachedNegativeRecord record : resolvedResponseEntry.getRecords()) {
        if (match != null)
        break;
        
        // check TTL
        if (record.getArrival() + record.getTTL() > this.messageUtils.getCurrentTime()) {
          if (record.matches(name)) match = record;
          if (record.inbetween(name)) cover = record;
        }
      }
    }

    if (match != null) return match;

    return cover;
  }

  // return true if a positive record exists for the queried name and type
  private boolean wildcardIsCached(Name wildcardName, int questionType) {
    wildcardName = wildcardName.canonicalize();
    CachedWildcardRecord wildcard = this.wildcardCache.get(wildcardName.canonicalize().toString());
    Name questionName = this.messageUtils.getQuestion().getName().canonicalize();
    
    return wildcard != null
      && wildcard.getArrival() + wildcard.getTTL() > this.messageUtils.getCurrentTime()
      && wildcard.getType() == questionType
      && questionName.compareTo(wildcardName) != 0;
  }

}