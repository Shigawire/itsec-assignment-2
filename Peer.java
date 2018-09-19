import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.StringTokenizer;
import java.math.BigInteger;

/**
 * Class that encapsulates all necessary means for implementing a simple
 * (blocking) peer client for realizing the Diffie-Hellman key exchange
 * protocol.
 *
 * @author Christian Grimme, 2018
 */
public class Peer {

	private static Socket socket = null;
	private static BufferedReader inputStream;
	private static PrintWriter outputStream;

	/**
	 * Method use to set up the reader and writer streams for an active socket.
	 * Used internally by waitForConnect() and connect().
	 */
	private static void setup() {
		try {
			inputStream = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			outputStream = new PrintWriter(socket.getOutputStream(), true);

		} catch (IOException e) {
			System.out.println("Reader or Writer could not be initialized.");
			System.exit(1);
		}
	}

	/**
	 * Method which waits for a connection request from a peer. This method
	 * should be used in passive mode, to keep on waiting. Therefore a
	 * SocketServer is set up to listen on the given port for a specified period
	 * of time.
	 *
	 * @param port
	 *            Post to listen on for connection requests.
	 * @param timeout
	 *            Maximum waiting time (milliseconds)
	 * @return Boolean value (true/false) indicating, whether a socket was
	 *         created.
	 */
	private static boolean waitForConnect(int port, int timeout) {
		if (socket == null) {
			ServerSocket ssocket;
			try {

				ssocket = new ServerSocket();

				System.out.println("Starting up.");

				ssocket.bind(new InetSocketAddress(port));

				System.out.println("Waiting at port " + port);

				try {

					ssocket.setSoTimeout(timeout);
					socket = ssocket.accept();

					System.out.println("Socket connection accepted.");

					setup();

				} catch (SocketTimeoutException ste) {
					System.out.println("A Timeout occured. No connection possible.");
				} catch (IOException ioe) {
					ioe.printStackTrace();
				} catch (SecurityException se) {
					se.printStackTrace();
				} catch (IllegalArgumentException iae) {
					iae.printStackTrace();
				} finally {
					ssocket.close();
				}

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return socket != null;
		} else {
			System.out.println("Socket already exists. Only one connection allowed.");
			return true;
		}
	}

	/**
	 * Method to start a connection. This method complements the
	 * <code>waitForConnect</code> method. It should be used to actively
	 * initialize a socket connection.
	 *
	 * @param ip
	 *            Contact IP address.
	 * @param port
	 *            Contact port.
	 * @return Boolean (true/false) that indicates whether a connection has been
	 *         established.
	 */
	private static boolean connect(String ip, int port) {
		if (socket == null) {
			socket = new Socket();

			try {
				socket.connect(new InetSocketAddress(ip, port));
				System.out.println("Socket connection successful established.");

				setup();

			} catch (IOException e) {
				System.out.println("Connection to peer impossible: " + e.getLocalizedMessage());
				socket = null;
			}

			return socket != null;
		} else {
			System.out.println("Socket already exists. Only one connection allowed.");
			return true;
		}
	}

	/**
	 * Method for sending a message string via the socket connection.
	 *
	 * @param msg
	 *            The message sent.
	 */
	private static void send(String msg) {
		outputStream.println(msg);
	}

	/**
	 * Method to wait (blocking) for a message via the socket connection.
	 *
	 * @return The message received.
	 * @throws IOException
	 */
	private static String waitFor() throws IOException {
		String currData = null;
		while (currData == null) {
			currData = inputStream.readLine();
		}

		System.out.println("Received data by peer: " + currData);
		return currData;
	}

	/**
	 * Utility method for tokenizing a given string into a String array
	 * respecting a given delimiter.
	 *
	 * @param s
	 *            The String that shall be tokenized.
	 * @param delim
	 *            The delimiter separating the tokens.
	 * @return Array of tokens
	 */
	private static String[] tokenize(String s, String delim) {
		StringTokenizer st = new StringTokenizer(s, delim);
		String[] tokens = new String[st.countTokens()];
		int i = 0;
		while (st.hasMoreTokens()) {
			tokens[i] = st.nextToken();
			i++;
		}
		return tokens;
	}

	private static String operation(String s) {
		String[] tokens = tokenize(s, " ");
		return tokens[0];
	}

	private static long expmod(int a, int exp, int mod) {
 		/*
 		 * Implement efficient modular exponentiation (see java.math.BigInteger)
 		 */

	 	BigInteger bigA = BigInteger.valueOf(a);
		BigInteger bigExp = BigInteger.valueOf(exp);
		BigInteger bigMod = BigInteger.valueOf(mod);

	 	BigInteger key = bigA.modPow(bigExp, bigMod);
		return key.longValue();

	}

	/**
	 * Executes the key exchange protocol in passive mode (i.e., waiting for an
	 * active peer to contact this one)
	 *
	 * @param port
	 *            Port to listen for incoming messages.
	 */
	private static void passiveMode(int port) {

		waitForConnect(port, 200000);

		/*
		 * Wait for a PROP (propose) command comprising n and a values
		 */

		try {
			String message = waitFor();

			if (!operation(message).equals("PROP")) {
				throw new IllegalArgumentException("Expected PROP message.");
			}

			int a = 0;
			int n = 0;

			String[] tokenized = tokenize(message, " ");
			a = Integer.parseInt(tokenized[1]);
			n = Integer.parseInt(tokenized[2]);

			if (a <= 0 || n <= 0) {
				send("NAK");
				throw new IllegalArgumentException("Expected a and n parameters to be positive integers");
			}

			send("ACK");

			/*
				Now, create a secret x1
			*/

			SecureRandom rng = new SecureRandom();
			int x = rng.nextInt(50) + 50;

			System.out.println("My X is: " + x);

			long exchangeKey = expmod(a, x, n);

			System.out.println("My exchange key Y is: " + exchangeKey);

			send("KEY " + exchangeKey);


		} catch (IOException e) {
			System.out.println("Error receiving data.");
			System.exit(1);
		} catch(IllegalArgumentException e) {
			System.out.println("Error on data exchange.");
			System.exit(1);
		}
		/*
		 * Exchange key
		 */

	}

	/**
	 * Executes the peer in active mode (i.e., this peer starts the DH key
	 * exchange with a PROP message, sending a and n.
	 *
	 * @param ip
	 *            The remote IP.
	 * @param port
	 *            The port to send to.
	 */
	private static void activeMode(String ip, int port) {

        int a = 53;
        int n = 123457;
        SecureRandom x;

        /* TODO: implement PRNG for a and n */

        connect(ip, port);

        /*
         * Send PROP (propose) command comprising n and a values
         */

        send("PROP " + a + " " + n);

        /*
         * Exchange key
         */

        try {
            String answer = waitFor();

            if (answer.equals("ACK")) {
                System.out.println("The proposal of a and n was acknowledged.");

                x = new SecureRandom();

            } else {
                System.out.println("The proposal was not acknowledged.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

	// ----------------------- MAIN METHOD ---------------------
	public static void main(String[] args) {

		if (args.length < 1) {
            System.out.println("Usage: java Peer.java <active|passive>");
		} else {
			if (args.length  == 1 && args[0].equals("passive")) {
                passiveMode(1234);
            } else if(args.length == 2 && args[0].equals("active")) {
				activeMode(args[1], 1234);
			} else {
                System.out.println("Invalid arguments");
			}
		}

		try {
			socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
