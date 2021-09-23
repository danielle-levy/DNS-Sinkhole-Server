package il.ac.idc.cs.sinkhole;
import java.io.IOException;
import java.net.*;
import java.util.HashSet;
import java.util.Random;

public class UDPIterative
{
    static InetAddress[] DNSRootServers;
    static DatagramSocket serverSocket;

    static { //initializing all 13 DNS Root Servers
        try {
            DNSRootServers = new InetAddress[]{InetAddress.getByName("a.root-servers.net"),
                    InetAddress.getByName("b.root-servers.net"), InetAddress.getByName("c.root-servers.net"),
                    InetAddress.getByName("d.root-servers.net"), InetAddress.getByName("e.root-servers.net"),
                    InetAddress.getByName("f.root-servers.net"), InetAddress.getByName("g.root-servers.net"),
                    InetAddress.getByName("h.root-servers.net"), InetAddress.getByName("i.root-servers.net"),
                    InetAddress.getByName("j.root-servers.net"), InetAddress.getByName("k.root-servers.net"),
                    InetAddress.getByName("l.root-servers.net"), InetAddress.getByName("m.root-servers.net") };
        } catch (UnknownHostException e) {
            System.err.println("Root server address not found by name");
        }
    }

    static int RandomDnsRootServer = new Random().nextInt(DNSRootServers.length);


    public static void IterativeSeek(HashSet<String> hashSet)
    {
        // initializing components
        int port = 5300;
        int NOERROR = 0;
        byte[] recieveDataFromClient = new byte[1024];
        byte[] recieveDataFromServer = new byte[4096];
        try{
            serverSocket = new DatagramSocket(port);
        } catch(SocketException e) {
            System.err.println("Server couldn't initialize the socket");
        }
        InetAddress DnsRootServer = DNSRootServers[RandomDnsRootServer]; // chooses randomly a DNS Root Server
        DatagramPacket receivePacketFromUser = new DatagramPacket(recieveDataFromClient, recieveDataFromClient.length);
        DatagramPacket receivePacketFromServer = new DatagramPacket(recieveDataFromServer, recieveDataFromServer.length);
        
        while (true)
        {
            // listening on port 5300 for query from the client
            try{
                serverSocket.receive(receivePacketFromUser); // receiving the DNS query from the client to send to the DNS Root Server
            } catch (IOException e){
                System.err.println("Server couldn't receive query from the client");
            }
        InetAddress clientAddress = receivePacketFromUser.getAddress();
        int clientPort = receivePacketFromUser.getPort();
        receivePacketFromUser.setAddress(DnsRootServer);
        receivePacketFromUser.setPort(53);

        // checking if using blocklist and if so -> if the quary is in the blocklist, send the user proper quary
        if (hashSet != null)
        {
            String url = packetSniffing.getUrlName(receivePacketFromUser);
            if(hashSet.contains(url))
            {
                receivePacketFromUser.getData()[3] = (byte)0b10000011;
                receivePacketFromUser.getData()[2] = (byte)0b10000001;
                receivePacketFromUser.setAddress(clientAddress);
                receivePacketFromUser.setPort(clientPort);
                try{
                    serverSocket.send(receivePacketFromUser);
                } catch (IOException e){
                    System.err.println("Server couldn't send the packet back to the client");
                }
                continue;
            }
        }

        // sending the query to random DNS Root Server
            try{
                serverSocket.send(receivePacketFromUser);
            } catch (IOException e){
                System.err.println("Server couldn't send the query to random root DNS server");
            }
            try{
                serverSocket.receive(receivePacketFromServer); // waiting for response from the corresponding DNS Server
            } catch (IOException e){
                System.err.println("Server couldn't receive the response from the root DNS server");
            }

        // Running iteratively through the Authority DNS Servers and looking for an answer that not satisfies the while conditions (max 16 loops)
        int i = 0;
        while ((packetSniffing.getResponseCode(receivePacketFromServer) == NOERROR) && (packetSniffing.getNumOfAnsRecords(receivePacketFromServer) == 0) && (packetSniffing.getAuthority(receivePacketFromServer) > 0) && (i < 16))
        {
            String nextDNSserver = packetSniffing.getNextAuthority(receivePacketFromServer, (char)(RandomDnsRootServer + 97));
            try{
                receivePacketFromUser.setAddress(InetAddress.getByName(nextDNSserver));
            } catch (UnknownHostException e){
                System.err.println("Server couldn't find the name of the next Authority");
            }
            receivePacketFromUser.setPort(53);
            try{
                serverSocket.send(receivePacketFromUser);
            } catch (IOException e){
                System.err.println("Server couldn't send the packet to the next Authority server");
            }
            try{
                serverSocket.receive(receivePacketFromServer);
            } catch (IOException e){
                System.err.println("Server couldn't receive the packet from the Authority server");
            }
            i++;
        }

        // sending the response from the Server back to the client
        receivePacketFromServer.getData()[2] = (byte)0b10000001;
        byte t = (byte)((receivePacketFromServer.getData()[3] << 4) >>> 4);
        receivePacketFromServer.getData()[3] = (byte)(0b10000000 | t);
        receivePacketFromServer.setAddress(clientAddress);
        receivePacketFromServer.setPort(clientPort);
        try{
            serverSocket.send(receivePacketFromServer);
        } catch (IOException e){
            System.err.println("Server couldn't send the packet back to the client");
            }
        }
    }
}
