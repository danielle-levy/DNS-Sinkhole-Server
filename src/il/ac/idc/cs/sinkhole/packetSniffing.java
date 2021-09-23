package il.ac.idc.cs.sinkhole;
import java.net.DatagramPacket;
import java.net.InetAddress;

/*
This class implements methods that handles with bitwise operations on a given packets
 */
public class packetSniffing
{

  //extracting Authority
  public static int getAuthority (DatagramPacket packet)
  {
    int authority = 0;
    int buffer1;
    int buffer2;
    buffer1 = packet.getData()[8];
    buffer2 = packet.getData()[9];
    buffer1 = (buffer1 << 24) >>> 16;
    buffer2 = (buffer2 << 24) >>> 24;
    authority = buffer1 | buffer2;
    System.out.println("NUM OF AUTHORITIES = " + authority);

    return authority;
  }

  //extracting Response Code
  public static int getResponseCode (DatagramPacket packet)
  {
    int responseCode = 0;
    responseCode = packet.getData()[3];
    responseCode = (responseCode << 28) >>> 28;
    System.out.println("RESPONSE CODE = " + responseCode);

    return responseCode;
  }

  //extracting the number of answers
  public static int getNumOfAnsRecords (DatagramPacket packet)
  {
    int numOfAnsRecords = 0;
    int buffer1;
    int buffer2;
    buffer1 = packet.getData()[6];
    buffer2 = packet.getData()[7];
    buffer1 = (buffer1 << 24) >>> 16;
    buffer2 = (buffer2 << 24) >>> 24;
    numOfAnsRecords = buffer1 | buffer2;
    System.out.println("NUM OF ANSWERS = " + numOfAnsRecords);

    return numOfAnsRecords;
  }

  //extracting the next authority given from the server
  public static String getNextAuthority(DatagramPacket packet, char root) {
    String authorityName = "";
    int i = 12;

    while (packet.getData()[i] != 0)
    {
      i++;
    }
    i += 5;

    while (packet.getData()[i] != 0)
    {
      i++;
    }
    i += 10;

    if (root == 105)
    {
      root = 0;
      i++;
    }

    byte currentByteToRead = packet.getData()[i];
    if ((currentByteToRead & (byte) (-64)) == -64)
    {
      i = Reference(packet, i);
      currentByteToRead = packet.getData()[i];
    }
    while (packet.getData()[i] != 0)
    {
      for (int j = 0; j < currentByteToRead; j++)
      {
        i++;
        authorityName = authorityName + (char)(packet.getData()[i]);
      }

      authorityName = authorityName + ".";
      i++;
      currentByteToRead = packet.getData()[i];

      if ((currentByteToRead & (byte) (-64)) == -64)
      {
        i = Reference(packet, i);
        currentByteToRead = packet.getData()[i];
      }
    }

    authorityName = authorityName.substring(0, authorityName.length() - 1);

    return authorityName;
  }

  //extracting the QNAME (url) from a given quary
  public static String getUrlName(DatagramPacket packet)
  {
    byte refranceByte = -64;
    int i = 12;
    String urlName = "";
    byte currentbyteToRead = packet.getData()[i];

    if ((refranceByte & packet.getData()[i]) == refranceByte)
    {
      i = Reference(packet, i);
      currentbyteToRead = packet.getData()[i];
    }

    while (packet.getData()[i] != 0) {
      for (int j = 0; j < currentbyteToRead; j++)
      {
        i++;
        urlName = urlName + (char) (packet.getData()[i]);
      }
      urlName = urlName+".";
      i++;
      currentbyteToRead = packet.getData()[i];

      // checking if we are on a refrance byte
      if ((packet.getData()[i] & refranceByte) == refranceByte)
      {
        i = Reference(packet, i);
        currentbyteToRead = packet.getData()[i];
      }
    }

    urlName = urlName.substring(0, urlName.length() - 1);

    return urlName;
  }

  public static int Reference(DatagramPacket packet, int i)
  {
    int referance;
    byte currentByteToRead = packet.getData()[i];
    int curByte = (byte) (currentByteToRead & 0b00111111);
    int nextByteToRead = packet.getData()[i + 1];
    nextByteToRead = (nextByteToRead << 24) >>> 24;
    curByte = (curByte << 24) >>> 24;
    referance = (curByte << 8) | nextByteToRead;

    return referance;
  }
}
