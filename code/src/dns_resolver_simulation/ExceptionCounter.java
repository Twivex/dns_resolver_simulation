package dns_resolver_simulation;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ExceptionCounter {
  private HashMap<String, Integer> storage;
  private FileWriter file;
  private FileWriter logFile;

  public ExceptionCounter(Logger logger) {
    this.storage = new HashMap<String, Integer>();
    this.file = logger.getFileWriter("exceptions");
    this.logFile = logger.getFileWriter("exceptions-log");
  }

  private void logException(Exception e) throws IOException {
    this.logFile.add(e.toString() + " in ");
    int counter = 0;
    for (StackTraceElement element : e.getStackTrace()) {
      this.logFile.add(element.getFileName() + ":" + Integer.toString(element.getLineNumber()));
      counter++;
      if (counter == e.getStackTrace().length - 1) break;
    }
    this.logFile.add("");
    this.logFile.write();
  }

  public void add(String exceptionName) {
    Integer count = storage.get(exceptionName);
    count = count != null ? count : 0;
    storage.put(exceptionName, count + 1);
  }

  public void add(Exception exception) {
    try {
	  	logException(exception);
    } catch (IOException e) {
      e.printStackTrace();
  	}
    add(exception.getClass().getSimpleName());
  }

  public void writeAll() {
    this.file.add("--- Exceptions ---");

    if (this.storage.isEmpty()) {
      this.file.add("** no exceptions **");
    } else {
      for (Map.Entry<String, Integer> entry : this.storage.entrySet()) {
        this.file.add(entry.getKey() + " - " + entry.getValue());
      }
    }

    try {
      this.file.write();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
