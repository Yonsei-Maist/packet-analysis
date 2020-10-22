package packet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Scanner;

public class PacketCapture {

    public static StringBuilder errorBuffer;
    public static PcapIf netInterface;
    public static Pcap pcap;

    /**
     * Get a list of devices
     */
    public void findNetworkDevice() {

        Scanner scanner = new Scanner(System.in);
        errorBuffer = new StringBuilder(); // error
        ArrayList<PcapIf> allDevice = new ArrayList<PcapIf>(); // list of devices

        int statusCode = Pcap.findAllDevs(allDevice, errorBuffer);
        if(statusCode != Pcap.OK || allDevice.isEmpty()) {
            System.out.println("Error occurred:" + errorBuffer.toString());
            return;
        }

        for (int i=0; i<allDevice.size(); i++) {
            String description = "";
            if(allDevice.get(i).getDescription() != null){
                description = allDevice.get(i).getDescription();
            }
            else {
                description = "No device description.";
            }
            System.out.println("#" + i + ": " + allDevice.get(i).getName() + ":" + description);
        }
        System.out.print("Enter device number :");
        int deviceIndex = scanner.nextInt();

        netInterface = allDevice.get(deviceIndex); // selected device
    }

    /**
     * Open a network interface for live capture
     */
    public void packetOpen() {

        int snaplen = 64 * 1024; // Truncate packet at this size
        int flags = Pcap.MODE_NON_PROMISCUOUS;
        int timeout = 10 * 1000; // in milliseconds
        pcap = Pcap.openLive(netInterface.getName(), snaplen, flags, timeout, errorBuffer);

        if(pcap == null) {
            System.out.println("Network interface access error : " + errorBuffer.toString());
            return;
        }
    }

    /**
     * Create a pcap file
     * @param packetCount capture packet count
     * @throws Exception all of error
     */
    public void packetDumper(int packetCount) throws Exception {

        SimpleDateFormat format = new SimpleDateFormat ( "yyyy-MM-dd HHmmss");
        String dateTime = format.format (System.currentTimeMillis());

        String fileName = "packet-" + dateTime +".pcap";
        String filePath = "C:/temp/packet_capture";
        String fullPath =  filePath + "/" + fileName;

        Path path = Paths.get(filePath);
        if(Files.notExists(path)) {
            Files.createDirectories(path);
        }

        final PcapDumper dumper = pcap.dumpOpen(fullPath);
        System.out.println("Capturing packets ....");

        PcapPacketHandler<PcapDumper> dumpHandler = new PcapPacketHandler<PcapDumper>() {
            @Override
            public void nextPacket(PcapPacket pcapPacket, PcapDumper pcapDumper) {
                dumper.dump(pcapPacket);
            }
        };

        pcap.loop(packetCount, dumpHandler, dumper);
        File file = new File(fullPath);
        System.out.printf("%s file has %d bytes in it!\n", fileName, file.length());

        dumper.close();
        pcap.close();
    }

    /**
     * View packet
     * @param packetCount packet count
     */
    public void printPacket(int packetCount) {

        PcapPacketHandler<String> jPacketHandelr = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user); // User supplied object

            }
        };
        pcap.loop(packetCount, jPacketHandelr, "jNetPcap");
    }
}
