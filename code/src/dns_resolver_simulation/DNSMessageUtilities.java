package dns_resolver_simulation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class DNSMessageUtilities {

  private Header dnsHeader;
  private Message message;
  private SOARecord soaRecord;
  private Record question;
  private Record[] answers;
  private Record[] authorities;
  private Record[] wildcards;
  private NSECRecord[] allNsecRecords;
  private NSEC3Record[] allNsec3Records;
  private double currentTime;

  public void set(Message message) {
    init();
    this.dnsHeader = message.getHeader();
    this.message = message;
  }

  public void setCurrentTime(double time) {
    this.currentTime = time;
  }

  public double getCurrentTime() throws RuntimeException {
    if (this.currentTime == 0)
      throw new RuntimeException("Current time not set");
    return this.currentTime;
  }

  public String getID() {
    return Integer.toHexString(this.dnsHeader.getID());
  }

  public boolean isResponse() {
    return this.dnsHeader.getFlag(Flags.QR);
  }

  public boolean isTruncated() {
    return this.dnsHeader.getFlag(Flags.TC);
  }

  public Record getQuestion() throws RuntimeException {
    if (this.question == null) setQuestion();
    return this.question;
  }

  public int questions() {
    Record question = this.message.getQuestion();
    return question != null ? 1 : 0;
  }
  
  public Record[] getAnswers() {
    if (this.answers == null) setAnswers();
    return this.answers;
  }

  public int answers() {
    Record[] answers = getAnswers();
    return answers == null ? 0 : answers.length;
  }

  public Record[] getAuthorities() {
    if (this.authorities == null) setAuthorities();
    return this.authorities;
  }

  public int authorities() {
    Record[] authorities = getAuthorities();
    return authorities == null ? 0 : authorities.length;
  }

  public SOARecord getSOARecord() {
    if (this.soaRecord == null) setSOARecord();
    return this.soaRecord;
  }

  public NSECRecord[] getAllNSECRecords() {
    if (this.allNsecRecords == null) setAllNSECRecords();
    return this.allNsecRecords;
  }

  public int allNSECRecords() {
    Record[] allNSECRecords = getAllNSECRecords();
    return allNSECRecords == null ? 0 : allNSECRecords.length;
  }

  public NSEC3Record[] getAllNSEC3Records() {
    if (this.allNsec3Records == null) setAllNSEC3Records();
    return this.allNsec3Records;
  }

  public int allNSEC3Records() {
    Record[] allNSEC3Records = getAllNSEC3Records();
    return allNSEC3Records == null ? 0 : allNSEC3Records.length;
  }

  public RRSIGRecord getRRSIGRecord(Name name, int section, int coveredType) throws RuntimeException {
    RRSIGRecord[] allSigRecords = Arrays.stream(this.message.getSectionArray(section))
        .filter(rec -> rec.getType() == Type.RRSIG)
        .toArray(RRSIGRecord[]::new);

        RRSIGRecord[] match = Arrays.stream(allSigRecords)
        .filter(rec -> rec.getTypeCovered() == coveredType && rec.getName().canonicalize().compareTo(name.canonicalize()) == 0)
        .toArray(RRSIGRecord[]::new);

    if (match == null || match.length == 0)
      // return null;
      throw new RuntimeException("RRSIG for " + Type.string(coveredType) + " not found in " + Section.longString(section));

    if (match.length == 1)
      return match[0];

    if (match.length > 1)
      throw new RuntimeException("Ambiguous RRSIG");

    return null;
  }

  public Record[] getWildcards() {
    if (this.wildcards == null) setWildcards();
    return this.wildcards;
  }

  public int wildcards() {
    Record[] wildcards = getWildcards();
    return wildcards == null ? 0 : wildcards.length;
  }

  public double obtainNegativeTTL(Long recordTTL) {
    ArrayList<Long> listOfTTL = new ArrayList<Long>();
    SOARecord soaRecord = this.getSOARecord();
    if (soaRecord != null) {
      listOfTTL.add(soaRecord.getMinimum());
      listOfTTL.add(soaRecord.getTTL());
    }
    listOfTTL.add(recordTTL);
    listOfTTL.add(Constants.MAX_TTL);
    Collections.sort(listOfTTL);

    return Long.valueOf(listOfTTL.get(0)).doubleValue();
  }

  public int getResponseType() throws RuntimeException, NameTooLongException {
    if (!isResponse())
      throw new RuntimeException("Response type cannot be declared on queries");

    if (wildcards() > 0)
      return Constants.WILDCARD_ANSWER_RESPONSE;

    Record question = getQuestion();
    Name questionName = question.getName().canonicalize();
    int questionType = question.getType();

    if (allNSECRecords() > 0) {
      EnhancedNSECRecord[] nsecRecords = (EnhancedNSECRecord[]) Arrays.stream(getAllNSECRecords())
          .map(r -> new EnhancedNSECRecord(r))
          .toArray(EnhancedNSECRecord[]::new);
      for (EnhancedNSECRecord nsecRecord : nsecRecords) {
        if (nsecRecord.matches(questionName) && !nsecRecord.hasType(questionType))
          return Constants.NO_DATA_RESPONSE;
        if (nsecRecord.getName().isWild() && !nsecRecord.hasType(questionType)) {
          return Constants.WILDCARD_NO_DATA_RESPONSE;
        }
      }
      return Constants.NAME_ERROR_RESPONSE;
    } else if (allNSEC3Records() > 0) {
      EnhancedNSEC3Record[] nsec3Records = (EnhancedNSEC3Record[]) Arrays.stream(getAllNSEC3Records())
          .map(r -> new EnhancedNSEC3Record(r))
          .toArray(EnhancedNSEC3Record[]::new);
      Name wildcardName = null;
      for (int index = 0; index < nsec3Records.length; index++) {
        EnhancedNSEC3Record nsec3Record = nsec3Records[index];
        if (nsec3Record.matches(question.getName()) && !nsec3Record.hasType(questionType))
          return Constants.NO_DATA_RESPONSE;
        
        if (wildcardName == null) {
          wildcardName = nsec3Record.getWildcardName(questionName);
          if (wildcardName != null) index = -1;
        }

        if (wildcardName != null) {
          if (nsec3Record.matches(wildcardName))
            return Constants.WILDCARD_NO_DATA_RESPONSE;
        }
      }
      return Constants.NAME_ERROR_RESPONSE;
    } else if (answers() > 0) {
      return Constants.RESPONSE;
    }
    else if (answers() == 0 && allNSECRecords() == 0 && allNSEC3Records() == 0) {
      return Constants.EMPTY_RESPONSE;
    }
    throw new RuntimeException("Response type cannot be declared");
  }

  private void init() {
    this.soaRecord = null;
    this.question = null;
    this.answers = null;
    this.authorities = null;
    this.wildcards = null;
    this.allNsecRecords = null;
    this.allNsec3Records = null;
    this.currentTime = 0;
  }

  private void setQuestion() throws RuntimeException {
    this.question = this.message.getQuestion();
    if (this.question == null)
      throw new RuntimeException("Question not found");
  }

  private void setAnswers() {
    this.answers = this.message.getSectionArray(Section.ANSWER);
  }

  private void setAuthorities() {
    this.authorities = this.message.getSectionArray(Section.AUTHORITY);
  }

  private void setSOARecord() {
    this.soaRecord = (SOARecord) Arrays.stream(getAuthorities())
        .filter(rec -> rec.getType() == Type.SOA)
        .findFirst()
        .orElse(null);
  }

  private void setAllNSECRecords() {
    this.allNsecRecords = Stream.concat(Arrays.stream(getAuthorities()), Arrays.stream(getAnswers()))
        .filter(rec -> rec.getType() == Type.NSEC)
        .toArray(NSECRecord[]::new);
  }

  private void setAllNSEC3Records() {
    this.allNsec3Records = Stream.concat(Arrays.stream(getAuthorities()), Arrays.stream(getAnswers()))
        .filter(rec -> rec.getType() == Type.NSEC3).toArray(NSEC3Record[]::new);
  }

  private void setWildcards() {
    List<Record> wildcards = new ArrayList<Record>();
    Name answerName;
    for (Record answer : this.getAnswers()) {
      if (answer.getType() == Type.RRSIG)
        continue;

      answerName = answer.getName();
      RRSIGRecord answerRRSIGRecord;
      try {
         answerRRSIGRecord = getRRSIGRecord(answerName, Section.ANSWER, answer.getType());
      } catch (RuntimeException e) {
        continue;
      }

      if (answerRRSIGRecord == null)
        continue;

      // - 1 bcs root does not count (RFC4034 Section 3.1.3)
      if (answerName.labels() - 1 > answerRRSIGRecord.getLabels()) {
        wildcards.add(answer);
      }
    }
    this.wildcards = wildcards.toArray(new Record[wildcards.size()]);
  }

}