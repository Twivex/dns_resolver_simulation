package dns_resolver_simulation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.utils.base32;

public class EnhancedNSEC3Record extends NSEC3Record {

  private static final long serialVersionUID = 1L;

  private base32 base32Converter;

  public EnhancedNSEC3Record(NSEC3Record record) {
    super(
      record.getName(),
      record.getDClass(),
      record.getTTL(),
      record.getHashAlgorithm(),
      record.getFlags(),
      record.getIterations(),
      record.getSalt(),
      record.getNext(),
      record.getTypes()
    );
    this.base32Converter = new base32(base32.Alphabet.BASE32HEX, false, false);
  }

  public boolean inbetween(Name needle) {
    try {
      String hashedNeedle = this.base32Converter.toString(calculateHash(needle));
      Name name = new Name(getName().getLabelString(0)).canonicalize();
      Name hashedNeedleName = new Name(hashedNeedle).canonicalize();
      Name next = new Name(DatatypeConverter.printHexBinary(getNext())).canonicalize();

      // if the next name lays before the owner name, it's currently the record for the last name of the chain
      // so the needle has only to lay after the owner name
      if (name.compareTo(next) > 0)
        return name.compareTo(hashedNeedleName) < 0;

      return name.compareTo(hashedNeedleName) < 0 && next.compareTo(hashedNeedleName) > 0;
    } catch (NoSuchAlgorithmException | TextParseException e) {
      System.err.println(e.getMessage());
      return false;
    }
  }

  public boolean matches(Name needle) {
    try {
      byte[] hashValue = calculateHash(needle);
      Name name = new Name(getName().getLabelString(0)).canonicalize();
      Name hashedNeedle = new Name(base32Converter.toString(hashValue)).canonicalize();
      return name.compareTo(hashedNeedle) == 0;
    } catch (NoSuchAlgorithmException | TextParseException e) {
      System.err.println(e.getMessage());
      return false;
    }
  }

  public Name getClosestEncloser(Name needle) {
    needle = needle.canonicalize();
    Name closestEncloser = null;
    Name currentName;
    for (int position = 0; closestEncloser == null && position < needle.labels() - 1; position++) {
      currentName = Name.fromConstantString(RecordUtilities.getCustomLabelString(needle, position));
      if (matches(currentName)) {
        closestEncloser = currentName;
      }
    }
    return closestEncloser;
  }

  public Name getWildcardName(Name questionName) throws NameTooLongException {
    Name closestEncloser = getClosestEncloser(questionName);
    if (closestEncloser == null) return null;
    return Name.concatenate(Name.fromConstantString("*"), getClosestEncloser(questionName));
  }

  /* initial call of the hash function
   * @params Name input                 value to be hashed
   * @throws NoSuchAlgorithmException   source: hash(...) -> MessageDigst.getInstance(...)
   * @return byte[]                     the calculated hash
   */
  public byte[] calculateHash(Name input) throws NoSuchAlgorithmException {
    byte[] hash = null;
    if (getSalt() == null) {
      hash = hash(input.toWireCanonical(), getIterations());
    } else {
      hash = hash(input.toWireCanonical(), getSalt(), getIterations());
    }
    return hash;
  }

  /* same as other function named 'hash', but without using any salt
   * @params byte[] input       value to be hashed
   * @params int    iterations  number of hash iterations
   * @return byte[]             the calculated hash
   */
  private byte[] hash(byte[] input, int iterations) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
    if (iterations > 0) {
      byte[] hash = messageDigest.digest(hash(input, iterations - 1));
      return hash;
    } else {
      byte[] hash = messageDigest.digest(input);
      return hash;
    }
  }

  /* function defined by RFC 5155 Section 5 "Calculation of the Hash" as follows:
   * IH(salt, x, 0) = H(x || salt), and
   * IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
   * @params byte[] input       value to be hashed
   * @params byte[] salt        value to be appended after the input before hash is calculated
   * @params int    iterations  number of hash iterations
   * @return byte[]             the calculated hash
   */
  private byte[] hash(byte[] input, byte[] salt, int iterations) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
    if (iterations > 0) {
      byte[] hash = messageDigest.digest(concatByteArrays(hash(input, salt, iterations - 1), salt));
      return hash;
    } else {
      byte[] hash = messageDigest.digest(concatByteArrays(input, salt));
      return hash;
    }
  }

  private byte[] concatByteArrays(byte[] a, byte[] b) {
    byte[] c = new byte[a.length + b.length];
    System.arraycopy(a, 0, c, 0, a.length);
    System.arraycopy(b, 0, c, a.length, b.length);
    return c;
  }
}