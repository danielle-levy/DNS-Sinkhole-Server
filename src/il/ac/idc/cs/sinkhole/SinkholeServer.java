package il.ac.idc.cs.sinkhole;
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

class SinkholeServer
{
    public static void main(String[] args)
    {
        BufferedReader br;
        if (args.length > 0)
        {
            // initializing a hash set of the urls in the blocklist
            HashSet<String> hashSet = new HashSet<String>();
            try{
                br = new BufferedReader(new FileReader(new File(args[0])));
                try {
                    String line;
                    while ((line = br.readLine()) != null) {
                        hashSet.add(line);
                    }
                    br.close();
                } catch (IOException e){
                    System.err.println("Couldn't read the text file properly");
                }
            } catch (FileNotFoundException e){
                System.err.println("path not found");
            }
            UDPIterative.IterativeSeek(hashSet);
        }
        else {
            UDPIterative.IterativeSeek(null);
        }
    }
}