package dns_resolver_simulation;

import org.xbill.DNS.Name;

public final class RecordUtilities {
  
  // builds a full domain name starting at label[startPos] and ending at the last (right) label
  public static String getCustomLabelString(Name name, int startPos) {
    if (startPos == 0) {
      return name.canonicalize().toString();
    }
    name = name.canonicalize();
    int labels = name.labels() - 1;
    int labelsCount = labels - startPos;
    String[] newLabels = new String[labelsCount];
    for (int i = startPos; i < labels; i++) {
      newLabels[i - startPos] = name.getLabelString(i);
    }
    return String.join(".", newLabels) + ".";
  }

}