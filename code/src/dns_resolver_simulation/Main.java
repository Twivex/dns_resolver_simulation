package dns_resolver_simulation;

import java.io.IOException;

public class Main {

	public static void main(String[] args) {
		try {
			Simulator simulator = new Simulator();
			simulator.readFile(args[0]);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
