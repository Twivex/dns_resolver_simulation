package dns_resolver_simulation;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

public class FileWriter {
  private String pathName;
  private String fileName;
  private String fileType;
  private List<String> lines;

  public FileWriter(String pathName, String fileName) {
    this.pathName = pathName;
    this.fileName = fileName;
    this.fileType = "txt";
    this.lines = new ArrayList<String>();
  }

  public FileWriter(String pathName, String fileName, String fileType) {
    this.pathName = pathName;
    this.fileName = fileName;
    this.fileType = fileType;
    this.lines = new ArrayList<String>();
  }

  public void add(String line) {
    this.lines.add(line);
  }

  public void write() throws IOException {
    Path path = Paths.get(this.pathName + "/" + this.fileName + "." + this.fileType);
    File file = path.toFile();
    if (!file.exists()) file.createNewFile();
    Files.write(path, this.lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
    this.lines.clear();
  }
}