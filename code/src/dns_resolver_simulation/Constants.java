package dns_resolver_simulation;

public final class Constants {

  /*
   * constants for IP addresses
   */
  public static final String RESOLVER_ADDR = "240.12.227.28";
  public static final String INTERNAL_ADDR_OFFSET = "240";

  /*
   * constants for time measurement
   */
  public static final double MILLI_SECOND = 0.001;
  public static final long MAX_TTL = 10800;               // <=> 3 hourds


  /*
   * constants for log process
   */
  public static final String LOG_PATH = "./logs";
  public static final String CACHE_HIT_STATISTICS = "cache_hit";
  public static final String ALL_STATISTICS = "all";
  public static final String CORRECT_RESPONSE_TYPE = "correct_response_type";


  /*
   * constants for response type identification
   */
  public static final int EMPTY_RESPONSE = -1;
  public static final int RESPONSE = 0;
  public static final int NO_RESPONSE = 1;
  public static final int NO_DATA_RESPONSE = 2;
  public static final int NAME_ERROR_RESPONSE = 3;
  public static final int WILDCARD_NO_DATA_RESPONSE = 4;
  public static final int WILDCARD_ANSWER_RESPONSE = 5;
}