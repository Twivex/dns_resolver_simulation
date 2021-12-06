package dns_resolver_simulation;

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {

  private String pathName;

  public Logger() {
    String dateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyy-MM-dd_HH-mm"));
    this.pathName = Constants.LOG_PATH + "/" + dateTime;
    (new File(this.pathName)).mkdir();
  }

  public FileWriter getFileWriter(String fileName) {
    return new FileWriter(this.pathName, fileName);
  }

  public FileWriter getFileWriter(String fileName, String fileType) {
    return new FileWriter(this.pathName, fileName, fileType);
  }
}