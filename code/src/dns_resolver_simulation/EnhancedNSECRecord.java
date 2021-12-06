package dns_resolver_simulation;

import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;

public class EnhancedNSECRecord extends NSECRecord {
  private static final long serialVersionUID = 1L;

  public EnhancedNSECRecord(NSECRecord record) {
    super(
      record.getName(),
      record.getDClass(),
      record.getTTL(),
      record.getNext(),
      record.getTypes()
    );
  }

  public boolean matches(Name needle) {
    return getName().canonicalize().compareTo(needle.canonicalize()) == 0;
  }

  public boolean inBetween(Name needle) {
    // if the next name lays before the owner name, it's currently the record for the last name of the chain
    // so the needle has to lay before the owner name and after the next name
    if (getName().canonicalize().compareTo(getNext().canonicalize()) > 0) return getName().canonicalize().compareTo(needle) > 0 && getNext().canonicalize().compareTo(needle) < 0;

    return getName().canonicalize().compareTo(needle) < 0 && getNext().canonicalize().compareTo(needle) > 0;

  }

  public Name getClosestEncloser(Name needle) {
    needle = needle.canonicalize();
    Name closestEncloser = null;
    Name currentName;
    for (int position = 0; closestEncloser == null && position < needle.labels() - 1; position++) {
      currentName = Name.fromConstantString(RecordUtilities.getCustomLabelString(needle, position));
      if (getName().toString().indexOf(currentName.toString()) > -1) {
        closestEncloser = currentName;
      }
    }
    return closestEncloser;
  }

}