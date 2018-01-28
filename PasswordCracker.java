/*
	Simple password cracker for CSCI 345
	written by Brandi Durham, and Andrew Miller
 */

import java.util.Scanner;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.MessageDigest;
public class PasswordCracker{
		static File outputFile = new File("./output.txt");

        public static void main(String[] args) throws FileNotFoundException, IOException {
        //Clear output file from any previous run
        Writer writer = new FileWriter(outputFile);
        writer.close();
        String inputFilePath="";
        //Grab the filepath needed to iterate rules over
        if(args.length == 0){
            System.out.println("error no filepath specified as argument");
            System.exit(0);
        }
        else {
        	inputFilePath = args[0];
        }
        
        File inputFile = new File(inputFilePath);
        if(!inputFile.exists()){
        	System.out.println("error no file exist at provided filepath: " + inputFilePath);
        	System.exit(0);
        }
        if(inputFile.isDirectory()) {
        	System.out.println("error filepath points to a directory");
        	System.exit(0);
        }
        //Here the input file is guaranteed to exist and be a non-directory
        inputFile = new File(inputFilePath);
        String userResponse="";
        Scanner scan = new Scanner(System.in);
        while(userResponse.compareToIgnoreCase("q")!=0){
            //User needs to choose a rule to test
            System.out.println("Please select a rule to test:   Or 'q' to quit" +
            "\n" + "1.) All numbers (4 digits to 6 digits in length)" +
            "\n" + "2.) A four char word which gets the first letter capitalized and a 1-digit number appended." +
            "\n" + "3.) A five char word with the letter 'e' in it which gets replaced with a 3" +
            "\n" + "4.) Any single word from /usr/share/dict/words" +
            "\n" + "5.) Test iterating over password file using all available rules");
            userResponse = scan.next();
            if (userResponse.equals("1") || userResponse.equals("2") || userResponse.equals("3") || userResponse.equals("4") || userResponse.equals("5")) {
                //Here is where the rule has been selected and we need to actually start generating guesses based on it.
            	try (BufferedReader br = new BufferedReader(new FileReader(inputFile))) {
            	    String line;
            	    while ((line = br.readLine()) != null) {
            	    	//just separating out the hash of each line in the input testFile test will be ran against this hash
            	    	String[] splited = line.split("[\\:\\s]+");
            	    	String currentHash = splited[1];
            	    	//System.out.println(currentHash);
            	    	generateGuesses(Integer.parseInt(userResponse), currentHash);
            	    }
            	}
            }
        }
        scan.close();
        System.out.println("Exiting...");
        }

        private static String askForFilepath(){
        String inputFilePath;
        Scanner scan = new Scanner(System.in);
        System.out.println("Please provide a path to file containing hashed passwords.  Or 'q' to quit");
        inputFilePath = scan.next();
        if (inputFilePath.equals("q") || inputFilePath.equals("Q")){
            System.out.println("Exiting...");
            System.exit(0);
        }
        scan.close();
        return inputFilePath;
        }

        private static void generateGuesses(int ruleToTest, String currentHash) throws FileNotFoundException, IOException{
            switch (ruleToTest){
                case 1: //All numbers (4 digits to 6 digits in length)
                	boolean found = false;
                	
                	File wordsFile;
                	if (!found) {
	                	//check all 4 digits
	                    for(int i=0; i<=9999; i++) {
	                        String formattedPassword = String.format("%04d", i);
	                        if (MD5(formattedPassword).equalsIgnoreCase(currentHash)) {
	                        	System.out.println("\n" + "The Password is: " + i + "\n");
	                        	writeToFile(Integer.toString(i), currentHash, outputFile);
	                        	found = true;
	                        }
	                    }
	                    //check all 5 digits of course only if not already found
	                	if (!found) {
		                    for(int i=0; i<=99999; i++) {
		                        String formattedPassword = String.format("%05d", i);
		                        if (MD5(formattedPassword).equalsIgnoreCase(currentHash)) {
		                        	System.out.println("\n" + "The Password is: " + i + "\n");
		                        	writeToFile(Integer.toString(i), currentHash, outputFile);
		                        	found = true;
		                        }
		                    }
		                    //check all 6 digits of course only if not already found
		                	if (!found) {
			                    for(int i=0; i<=999999; i++) {
			                        String formattedPassword = String.format("%06d", i);
			                        if (MD5(formattedPassword).equalsIgnoreCase(currentHash)) {
			                        	System.out.println("\n" + "The Password is: " + i + "\n");
			                        	writeToFile(Integer.toString(i), currentHash, outputFile);
			                        	found = true;
			                        }
			                    }
		                    }
	                    }
                	}
                    
                    
                    break;
                case 2:
                	wordsFile = new File("/usr/share/dict/words");
                	try (BufferedReader br = new BufferedReader(new FileReader(wordsFile))) {
                	    String line;
                	    while ((line = br.readLine()) != null) {
                	    	if (line.length() == 4) {
                	    		for (int i=0; i<=9; i++) {
	                	    		String wordWithFirstCapAndTrailingNum = line.substring(0, 1).toUpperCase() + line.substring(1) + i;
		                	    	if (MD5(wordWithFirstCapAndTrailingNum).equalsIgnoreCase(currentHash)) {
		                	    		System.out.println("\n" + "The Password is: " + wordWithFirstCapAndTrailingNum + "\n");
		                	    		writeToFile(wordWithFirstCapAndTrailingNum, currentHash, outputFile);
		                	    	}
                	    		}
                	    	}
                	    }
                	}
                	break;
                case 3:
                	wordsFile = new File("/usr/share/dict/words");
                	try (BufferedReader br = new BufferedReader(new FileReader(wordsFile))) {
                	    String line;
                	    while ((line = br.readLine()) != null) {
                	    	if (line.length() == 5 && (line.contains("e") || line.contains("E"))) {
	                	    	for(int i=0; i<5; i++) {
	                	    		if (line.charAt(i)=='e' || line.charAt(i)=='E') {
	                	    			String temp = line;
	                	    			char[] array = temp.toCharArray();
	                	    			array[i] = '3';
	                	    			temp = new String(array);
				                	    if (MD5(temp).equalsIgnoreCase(currentHash)) {
				                	    	System.out.println("\n" + "The Password is: " + temp + "\n");
				                	    	writeToFile(temp, currentHash, outputFile);
				                	    }
	                	    		}
	                	    	}
                	    	}
                	    }
                	}
                	break;
                case 4: //Any single word from /usr/share/dict/words
                	wordsFile = new File("/usr/share/dict/words");
                	try (BufferedReader br = new BufferedReader(new FileReader(wordsFile))) {
                	    String line;
                	    while ((line = br.readLine()) != null) {
                	    	if (MD5(line).equalsIgnoreCase(currentHash)) {
                	    		System.out.println("\n" + "The Password is: " + line + "\n");
                	    		writeToFile(line, currentHash, outputFile);
                	    		break;
                	    	}
                	    }
                	}
                	break;
                case 5: //Test Using all rules
                	for(int i=1; i<5; i++) {
                		generateGuesses(i, currentHash);
                	}
                	break;
            }
        }
        
        //helper method to parse string and return MD5 hash as a string
        private static String MD5(String md5) {
        	   try {
        	        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        	        byte[] array = md.digest(md5.getBytes());
        	        StringBuffer sb = new StringBuffer();
        	        for (int i = 0; i < array.length; ++i) {
        	          sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1,3));
        	       }
        	        return sb.toString();
        	    } catch (java.security.NoSuchAlgorithmException e) {
        	    }
        	    return null;
        	}
        
        private static void writeToFile(String pass, String hash, File f) throws IOException {
        	Writer writerAfterClear = new FileWriter(f, true);
        	writerAfterClear.write(hash + ":" + pass + "\n");
        	writerAfterClear.close();
        }

}