import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.lang.instrument.Instrumentation;
import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

public class RainbowTable {

	private static HashMap<String, byte[]> table;
    private static MessageDigest SHA; // 160 bits
    private static final int CHAIN_LENGTH = 185; //MODIFY THIS PARAMETER
    private static final int NUMBER_OF_ROWS = 50000; //MODIFY THIS PARAMETER
    private static long smallT;
    private static long bigT;

	public static void main(String[] args) throws Exception {
        System.out.println("\nInitializing Rainbow Table Program...\n");
        //build the rainbow
		buildTable();
		//write the rainbow table to file (for checking of the rainbow table size)
        writeTableToFile();
        //gotta-go-fast
		speedTest();
        //attack!!!
		rainbowAttack();
	}

	private static void rainbowAttack() throws Exception {
        System.out.println("\nPHASE 3: RAINBOW ATTACK\n");
        System.out.print("ENTER THE INPUT FILE NAME: ");
		String fileName;
		Scanner sc = new Scanner(System.in);
		fileName = sc.nextLine();
        System.out.println("\nBEGINNING ATTACK...\n");
		BufferedReader br = new BufferedReader(new FileReader(fileName));
		String currentLine;
		int success = 0, reject = 0, counter = 0;
		byte[][] allDigests = new byte[1000][20]; //20 bytes = 160 bits SHA1
		byte[][] allWords = new byte[1000][3]; 
		//Reading from file
		while((currentLine = br.readLine()) != null) {
			String currentHexString;
			currentHexString = currentLine.substring(2,10) + currentLine.substring(12,20) + currentLine.substring(22,30) + currentLine.substring(32,40) + currentLine.substring(42,50);
			currentHexString = currentHexString.replaceAll("\\s", "0"); //replace spaces with 0
            //System.out.println(currentHexString);
			allDigests[counter] = hexToBytes(currentHexString);
            counter++;
		}
		br.close();
		FileWriter fw = new FileWriter("Results_Output.data");
		fw.write("S T A R T\n");
		fw.write("READ DONE\n");
		byte[] currentDigest, answer;
		long startTime = System.currentTimeMillis();
		for(int i = 0; i < allWords.length; i++) {
			currentDigest = allDigests[i];
			answer = invert(currentDigest);
			allWords[i] = answer;
			if(answer != null) {
				success++;
			}
		}
		long endTime = System.currentTimeMillis();
		//Write answers to file
		for(int i1 = 0; i1 < allWords.length; i1++) {
			if(allWords[i1] == null) {
				fw.write("\n 0");
			} else {
				fw.write("\n " + bytesToHex(allWords[i1]));
			}
		}
        smallT = endTime - startTime;
		fw.write("\n\nTotal number of words found: " + success + "\n");
		fw.close();
        System.out.println("> END OF ATTACK <");
        System.out.println("\n---- SUMMARY OF RESULTS ----\n");
		System.out.println("Total time for INVERT (Small t): " + (endTime - startTime)/1000.0 + " seconds.");
        System.out.println("Total number of words found: " + success);
        System.out.println("Percentage of words found (C)= " + success/10.0 + "%");
        System.out.println("Speedup Factor (F) = " + ((bigT * 1000)/smallT));
	}

	private static void buildTable() throws Exception {
        System.out.println("PHASE 1: CONSTRUCTING RAINBOW TABLE\n");
		long start, end;
		byte[] plain, word;
		String key;
		table = new HashMap<String, byte[]>();
		SHA = MessageDigest.getInstance("SHA1");
		Random R = new Random();
		int success = 0, collisions = 0, i = 0;
		start = System.currentTimeMillis();
		while(table.size() < NUMBER_OF_ROWS) {
			plain = intToBytes(i);
			word = generateSingleChain(plain, i);
			key = bytesToHex(word);
			if(!table.containsKey(key)) {
				table.put(key, plain);
				success++;
			} else {
				collisions++;
			}
			i++;
		}
		end = System.currentTimeMillis();
        System.out.println("> RAINBOW TABLE SPECIFICATIONS <\n");
        System.out.println("NUMBER OF ROWS: " +  NUMBER_OF_ROWS);
        System.out.println("LENGTH OF CHAIN: " + CHAIN_LENGTH);
		System.out.println("GENERATED RAINBOW TABLE IN: " + (end-start)/1000.0 + " SECONDS.\n");
	}

	private static void speedTest() throws Exception{
        System.out.println("\nPHASE 2: CALCULATING TIME TAKEN TO DO 2^23 SHA1 OPERATIONS\n");
		long start, end;
		byte[] word = new byte[3];
		Random r = new Random(30);
		r.nextBytes(word);
		start = System.currentTimeMillis();
		for(int i = 0; i < 8388608; i++) { //2^23 SHA1 operations
			byte[] temp = applyHash(word);
		}
		end = System.currentTimeMillis();
		bigT = (end-start);
		System.out.println("Time taken (Big T) : " + (end-start)/1000.0 + "\n");
        System.out.println("END OF PHASE 2\n");
	}

	private static byte[] generateSingleChain(byte[] plain, int ti) throws Exception {
        byte[] applyHash = new byte[20];
        byte[] word = plain;
        Random r = new Random();
        int di = r.nextInt(CHAIN_LENGTH);
        for (int i = 0; i < CHAIN_LENGTH; i++) {
            applyHash = applyHash(word);
            word = applyReduction(applyHash, i);
        }
        return word;
    }

    private static byte[] applyReduction(byte[] digest, int len) {
        byte last_byte = (byte) len;
        byte[] len_bytes = intToBytes(len);
        byte[] word = new byte[3];
        for (int i = 0; i < word.length; i++) {
            word[i] = (byte) (digest[(len + i) % 20] + last_byte);
        }
        return word;
    }

    private static byte[] applyHash(byte[] plaintext) {
        byte hash[] = new byte[20];
        try {
            hash = SHA.digest(plaintext);
            SHA.reset();
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
        return hash;
    }

    private static byte[] invert(byte[] hashToMatch) {
        byte[] result = new byte[3];
        String key = "";
        for (int i = CHAIN_LENGTH - 1; i >= 0; i--) {
            key = invertHR(hashToMatch, i);
            if (table.containsKey(key)) {
                result = invertChain(hashToMatch, table.get(key));
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }

    private static String invertHR(byte[] digest, int start) {
        byte[] word = new byte[3];
        for (int i = start; i < CHAIN_LENGTH; i++) {
            word = applyReduction(digest, i);
            digest = applyHash(word);
        }
        return bytesToHex(word);
    }

    private static byte[] invertChain(byte[] hashToMatch, byte[] word) {
        byte[] hash;
        for (int i = 0; i < CHAIN_LENGTH; i++) {
            hash = applyHash(word);
            if (Arrays.equals(hash, hashToMatch)) {
                return word;
            }
            word = applyReduction(hash, i);
        }
        return null;
    }

    private static byte[] hexToBytes(String hexString) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        byte[] bytes = adapter.unmarshal(hexString);
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        String str = adapter.marshal(bytes);
        return str;
    }

    private static byte[] intToBytes(int n) {
        byte plaintext[] = new byte[3];
        plaintext[0] = (byte) ((n >> 16) & 0xFF);
        plaintext[1] = (byte) ((n >> 8) & 0xFF);
        plaintext[2] = (byte) n;
        return plaintext;
    }

    private static void writeTableToFile() {
        System.out.println("WRITING TABLE TO: rainbow_table.data");
        ObjectOutputStream oos;
        try {
            oos = new ObjectOutputStream(new FileOutputStream("rainbow_table.data"));
            oos.writeObject(table);
            oos.close();
            System.out.println("WRITING SUCCESS!\n");
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
        System.out.println("END OF PHASE 1\n");
    }
}