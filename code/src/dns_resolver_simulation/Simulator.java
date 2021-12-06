package dns_resolver_simulation;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.Map;

import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.Record;

class Simulator {

	private SimulationCache simulationCache;
	private DNSMessageUtilities messageUtils;
	private SlidingWindow slidingWindow;
	private Statistics statistics;
	private ExceptionCounter exceptionCounter;
	private FileWriter logFile;
	// private FileWriter aliensFile;
	private FileWriter ipv6File;

	public Simulator() throws IOException {
		Logger logger = new Logger();
		this.statistics = new Statistics(logger, 2000, 1);
		this.messageUtils = new DNSMessageUtilities();
		this.simulationCache = new SimulationCache(this.messageUtils, this.statistics);
		this.slidingWindow = new SlidingWindow(this.messageUtils);
		this.logFile = logger.getFileWriter("log");
		this.aliensFile = logger.getFileWriter("unexpected");
		this.exceptionCounter = new ExceptionCounter(logger);
	}

	public void readFile(String pathname) throws IOException {
		printConfiguration(pathname);
		File file = new File(pathname);
		boolean firstTime = true;
		int counter = 0;

		if (file.exists() && file.isFile()) {
			InputStream stream = new BufferedInputStream(new FileInputStream(file));

			// variables for conversions
			double unixSeconds = 0;
			int ipVersion;
			String ipSrcString = "";
			String ipDstString = "";
			String portSrcString = "";
			String portDstString = "";

			// prepare bytes to read from stream, variables sorted by the byte order in the file
			byte[] magic;
			byte[] timestamp;
			byte[] frameNo;
			byte[] ipVer;
			byte[] srcIp;
			byte[] dstIp;
			byte[] transType;
			byte[] srcPort;
			byte[] dstPort;
			byte[] msgLength;

			Message dnsMessage = new Message();

			while (stream.available() > 0) {
				counter++;
				if (counter % 1000000 == 0)
					System.out.println(counter/1000000 + "M packages");

				/* * * * * * * * * * * * * *
				 * READ PACKAGE FROM FILE  *
				 * * * * * * * * * * * * * */
				magic = new byte[4];
				timestamp = new byte[8];
				frameNo = new byte[4];
				ipVer = new byte[1];
				srcIp = new byte[4];
				dstIp = new byte[4];
				transType = new byte[1];
				srcPort = new byte[2];
				dstPort = new byte[2];
				msgLength = new byte[2];


				/* MAGIC (only once) */
				if (firstTime) stream.read(magic);

				/* TIMESTAMP */
				stream.read(timestamp);
				unixSeconds = ByteBuffer.wrap(timestamp).order(ByteOrder.LITTLE_ENDIAN).getDouble();

				/* FRAME NUMBER */
				stream.read(frameNo);

				/* IP VERSION */
				stream.read(ipVer);
				ipVersion = Byte.toUnsignedInt(ipVer[0]);

				// increase size of byte arrays for IP addresses depending on IP version
				if (ipVersion == 6) {
					srcIp = new byte[16];
					dstIp = new byte[16];
				}

				/* SOURCE & DESTINATION IP ADDRESSES */
				stream.read(srcIp);
				stream.read(dstIp);
				ipSrcString = ipToString(srcIp, ipVersion);
				ipDstString = ipToString(dstIp, ipVersion);

				/* TRANSPORT TYPE */
				stream.read(transType);

				/* SOURCE & DESTIONATION PORTS */
				stream.read(srcPort);
				stream.read(dstPort);
				portSrcString = Integer.toString(uint16ToInt(srcPort));
				portDstString = Integer.toString(uint16ToInt(dstPort));


				/* DNS MESSAGE */
				stream.read(msgLength);
				byte[] msgBuf = new byte[uint16ToInt(msgLength)];
				stream.read(msgBuf);

				// remove first time flag
				firstTime = false;

				if (ipVersion == 4) {
					/* * * * * * * * * * * * * * *
					 * READ/PREPARE DNS MESSAGE  *
					 * * * * * * * * * * * * * * */
					dnsMessage = new Message();
					try {
						dnsMessage = new Message(msgBuf);
					} catch (Exception e) {
						this.exceptionCounter.add(e);
						continue;
					}

					this.messageUtils.set(dnsMessage);
					this.messageUtils.setCurrentTime(unixSeconds);

					/* * * * * * * * * * * * * * * *
					 * QUERY INTERNAL -> RESOLVER  *
					 * * * * * * * * * * * * * * * */
					if (
						this.messageUtils.isResponse() == false												// query
						&& ipSrcString.startsWith(Constants.INTERNAL_ADDR_OFFSET)			// source = internal
						&& ipDstString.equals(Constants.RESOLVER_ADDR)								// destination = resolver
					) {
						this.statistics.countInternalQuery();
						this.slidingWindow.setKey(ipSrcString, portSrcString);
						updateSlidingWindow();
					}
					/* * * * * * * * * * * * * * * *
					 * QUERY RESOLVER -> EXTERNAL  *
					 * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse() == false												// query
						&& ipSrcString.equals(Constants.RESOLVER_ADDR)								// source = resolver
						&& !ipDstString.startsWith(Constants.INTERNAL_ADDR_OFFSET)		// destination != internal
					) {
						this.statistics.countExternalQuery();
					}
					/* * * * * * * * * * * * * * * *
					 * QUERY RESOLVER -> INTERNAL  *
					 * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse() == false												// query
						&& ipSrcString.equals(Constants.RESOLVER_ADDR)								// source = resolver
						&& ipDstString.startsWith(Constants.INTERNAL_ADDR_OFFSET)			// destination = internal
					) {
						logAlienOccurrence("QUERY R -> INT", ipSrcString, portSrcString, ipDstString, portDstString);
					}
					/* * * * * * * * * * * * * * * *
					 * QUERY EXTERNAL -> RESOLVER  *
					 * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse() == false												// query
						&& !ipSrcString.startsWith(Constants.INTERNAL_ADDR_OFFSET)		// source != internal
						&& ipDstString.equals(Constants.RESOLVER_ADDR)								// destination = resolver
					) {
						logAlienOccurrence("QUERY EXT -> R", ipSrcString, portSrcString, ipDstString, portDstString);
					}
					/* * * * * * * * * * * * * * * * *
					 * RESPONSE EXTERNAL -> RESOLVER *
					 * * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse()																// response
						&& !ipSrcString.startsWith(Constants.INTERNAL_ADDR_OFFSET)		// source != internal
						&& ipDstString.equals(Constants.RESOLVER_ADDR)								// destination = resolver
					) {
						this.statistics.countExternalResponse();
						updateSimulationCache();
					}
					/* * * * * * * * * * * * * * * * *
					 * RESPONSE RESOLVER -> INTERNAL *
					 * * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse()																// response
						&& ipSrcString.equals(Constants.RESOLVER_ADDR)								// source = resolver
						&& ipDstString.startsWith(Constants.INTERNAL_ADDR_OFFSET)			// destination = internal
					) {
						this.statistics.countInternalResponse();
						this.slidingWindow.setKey(ipDstString, portDstString);
						clearSlidingWindow();
					}
					/* * * * * * * * * * * * * * * * *
					 * RESPONSE INTERNAL -> RESOLVER *
					 * * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse()															// response
						&& ipSrcString.startsWith(Constants.INTERNAL_ADDR_OFFSET)		// source = internal
						&& ipDstString.equals(Constants.RESOLVER_ADDR)							// destination = resolver
					) {
						// should not exists, bcs filtered before
						logAlienOccurrence("RESPONSE INT -> R", ipSrcString, portSrcString, ipDstString, portDstString);
					}
					/* * * * * * * * * * * * * * * * *
					 * RESPONSE RESOLVER -> EXTERNAL *
					 * * * * * * * * * * * * * * * * */
					else if (
						this.messageUtils.isResponse()															// response
						&& ipSrcString.equals(Constants.RESOLVER_ADDR)							// sourc = resolver
						&& !ipDstString.startsWith(Constants.INTERNAL_ADDR_OFFSET)	// destination != internal
					) {
						logAlienOccurrence("RESPONSE R -> EXT", ipSrcString, portSrcString, ipDstString, portDstString);
					}
					else {
						logAlienOccurrence("UNEXPECTED", ipSrcString, portSrcString, ipDstString, portDstString);
					}
				}
			}
			stream.close();
			String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyy/MM/dd HH:mm:ss"));
			System.out.println("Simulation finished at " + now);
			this.logFile.add("Simulation finished at " + now);
			this.logFile.write();

			this.statistics.writeAll();
			this.exceptionCounter.writeAll();
		}
	}

	private void printConfiguration(String pathname) throws IOException {
		String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyy/MM/dd HH:mm:ss"));
		String start = "Simulation started at " + now;
		String path = "Location of source file: " + pathname;

		this.logFile.add(start);
		this.logFile.add("RESOLVER_ADDR = " + Constants.RESOLVER_ADDR);
		this.logFile.add("INTERNAL_ADDR_OFFSET = " + Constants.INTERNAL_ADDR_OFFSET);
		this.logFile.add("LOG_PATH = " + Constants.LOG_PATH);
		this.logFile.add(path);
		this.logFile.write();

		System.out.println(start);
		System.out.println("RESOLVER_ADDR = " + Constants.RESOLVER_ADDR);
		System.out.println("INTERNAL_ADDR_OFFSET = " + Constants.INTERNAL_ADDR_OFFSET);
		System.out.println("LOG_PATH = " + Constants.LOG_PATH);
		System.out.println(path);
	}

	private void logAlienOccurrence(String direction, String ipSrc, String portSrc, String ipDst, String portDst) throws IOException {
		this.aliensFile.add(direction);
		this.aliensFile.add("src: " + ipSrc + ":" + portSrc);
		this.aliensFile.add("dst: " + ipDst + ":" + portDst);
		this.aliensFile.add("");
		this.aliensFile.write();
	}

	private void updateSlidingWindow() {
		try {
			int proof = this.simulationCache.proof();

			if (proof == Constants.NO_RESPONSE)
				this.statistics.countCacheMiss();
			else
				this.statistics.countCacheHit();

			this.slidingWindow.addEntry(proof);
		} catch (RuntimeException e) {
			if (e.getMessage() != null)
				this.exceptionCounter.add(e.getMessage());
			else
				this.exceptionCounter.add(e);
		} catch (NameTooLongException e) {
			this.exceptionCounter.add(e);
		}
	}

	private void updateSimulationCache() throws IOException {
		try {
			if (this.messageUtils.allNSECRecords() > 0 || this.messageUtils.allNSEC3Records() > 0) {
				this.simulationCache.add();
			}
			if (this.messageUtils.wildcards() > 0) {
				this.statistics.countExternalWildcardResponse();
				this.simulationCache.addWildcard();
			}
		} catch (RuntimeException e) {
			if ((e.getMessage().startsWith("RRSIG for NSEC not found") || e.getMessage().startsWith("RRSIG for NSE3C not found"))
				&& this.messageUtils.isTruncated())
			{
				this.statistics.countTruncatedRRSIG();
			}
			if (e.getMessage() != null)
				this.exceptionCounter.add(e.getMessage());
			else
				this.exceptionCounter.add(e);
		}
	}

	private void clearSlidingWindow() throws IOException {
		// look for query in sliding windows
		QueryEntry foundQueryEntry = null;
		try {
			foundQueryEntry = this.slidingWindow.getEntry();
		} catch (RuntimeException e) {
			if (e.getMessage() != null)
				this.exceptionCounter.add(e.getMessage());
			else
				this.exceptionCounter.add(e);
		}

		// store latency saving for statistics
		if (foundQueryEntry != null) {
			try {
				double current = this.messageUtils.getCurrentTime();
				double past = foundQueryEntry.arrival;
				this.statistics.saveLatencyStatistic(Constants.ALL_STATISTICS, current, past, false);

				// if there was a response based on cache, check if it was right
				if (foundQueryEntry.cacheResponse != Constants.NO_RESPONSE) {
					this.statistics.saveLatencyStatistic(Constants.CACHE_HIT_STATISTICS, current, past, true);
					int realResponseType = this.messageUtils.getResponseType();
					if (foundQueryEntry.cacheResponse == realResponseType)  {
						this.statistics.saveLatencyStatistic(Constants.CORRECT_RESPONSE_TYPE, current, past, false);
					} else {
						this.statistics.countFalsePositive();
					}
				} else {
					this.statistics.saveLatencyStatistic(Constants.CACHE_HIT_STATISTICS, current, past, false);
				}
			} catch (NameTooLongException e) {
				this.exceptionCounter.add(e);
			} catch (RuntimeException e) {
				if (e.getMessage() != null)
					this.exceptionCounter.add(e.getMessage());
				else
					this.exceptionCounter.add(e);
			}
		}

		slidingWindow.removeEntry();
	}

	private int uint16ToInt(byte[] bytes) {
		return (((0xFF & bytes[1]) << 8) | (0xFF & bytes[0]));
	}

	private String ipToString(byte[] bytes, int version) {
		String address = "";
		if (version == 4) {
			address = Byte.toUnsignedInt((byte) (0xFF & bytes[0])) + "." + Byte.toUnsignedInt((byte) (0xFF & bytes[1])) + "." + Byte.toUnsignedInt((byte) (0xFF & bytes[2])) + "." + Byte.toUnsignedInt((byte) (0xFF & bytes[3]));
		}
		else if (version == 6) {
			address = Integer.toHexString(((0xFF & bytes[0]) << 8) | (0xFF & bytes[1])) + ":" + Integer.toHexString(((0xFF & bytes[2]) << 8) | (0xFF & bytes[3])) + ":" +
			Integer.toHexString(((0xFF & bytes[4]) << 8) | (0xFF & bytes[5])) + ":" + Integer.toHexString(((0xFF & bytes[6]) << 8) | (0xFF & bytes[7])) + ":" +
			Integer.toHexString(((0xFF & bytes[8]) << 8) | (0xFF & bytes[9])) + ":" + Integer.toHexString(((0xFF & bytes[10]) << 8) | (0xFF & bytes[11])) + ":" +
			Integer.toHexString(((0xFF & bytes[12]) << 8) | (0xFF & bytes[13])) + ":" + Integer.toHexString(((0xFF & bytes[14]) << 8) | (0xFF & bytes[15]));
		}
		return address;
	}

}
