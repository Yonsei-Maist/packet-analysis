/**
 * @Author Mina Kim, Yonsei Univ. Researcher, since 2020.08. ~
 * @Author Chanwoo Gwon, Yonsei Univ. Researcher, since 2020.05. ~
 * @Date 2020.10.22
 */

package packet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

/**
 * Packet capture class (singleton design)
 * 1. capture the packet of server
 * 2. save to .pcap file all packet
 * 3. start/stop thread pool
 * 4. loop to capture / save file each {packetCapture} packets are captured
 */
public class PacketCapture {
    public static StringBuilder errorBuffer;
    public static PacketCapture instance = null;
    public static PacketCapture getInstance(String baseURL) throws Exception {
        if (instance != null)
            return instance;

        return new PacketCapture(baseURL);
    }

    public HashMap<PcapIf, Pcap> netInterface = new HashMap<PcapIf, Pcap>();

    private ArrayList<PCAPLooper> threadPool = new ArrayList<PCAPLooper>();
    private String baseURL = "";

    private PacketCapture(String baseURL) throws Exception {
        this.baseURL = baseURL;
        String os = System.getProperty("os.name");
        String arch = System.getProperty("os.arch");
        System.out.println(os);
        System.out.println(arch);
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        URL url = null;

        // load native library
        if (os.toLowerCase().contains("windows")) {
            url = classloader.getResource("windows64/jnetpcap.dll");
        } else if (os.toLowerCase().contains("linux")) {
            if (arch.contains("amd64")) {
                url = classloader.getResource("linux-amd64/libjnetpcap.so");
            } else {
                url = classloader.getResource("linux-i386/libjnetpcap.so");
            }
        }

        if (url != null) {
            System.load(url.getPath());
        } else {
            throw new Exception("We do not support this os.");
        }
    }
    /**
     * Get a list of devices
     */
    public void findNetworkDevice() {

        int snaplen = 64 * 1024; // Truncate packet at this size
        int flags = Pcap.MODE_NON_PROMISCUOUS;
        int timeout = 10 * 1000; // in milliseconds

        errorBuffer = new StringBuilder(); // error
        ArrayList<PcapIf> allDevice = new ArrayList<PcapIf>(); // list of devices

        int statusCode = Pcap.findAllDevs(allDevice, errorBuffer);
        if(statusCode != Pcap.OK || allDevice.isEmpty()) {
            System.out.println("Error occurred:" + errorBuffer.toString());
            return;
        }

        for (PcapIf pcapIf : allDevice) {
            Pcap pcap = Pcap.openLive(pcapIf.getName(), snaplen, flags, timeout, errorBuffer);

            if(pcap != null) {
                netInterface.put(pcapIf, pcap);
                // return;
            }
        }

        if (netInterface.size() == 0) {
            System.out.println("Network interface access error : " + errorBuffer.toString());
        }
    }

    /**
     * Create a pcap file
     * @param packetCount capture packet count
     * @throws Exception all of error
     */
    public void packetDumper(int packetCount) throws Exception {

        for (PcapIf pcapIf: this.netInterface.keySet()) {
            Pcap value = this.netInterface.get(pcapIf);

            Path path = Paths.get(this.baseURL);
            if(Files.notExists(path)) {
                Files.createDirectories(path);
            }

            PCAPLooper looper = new PCAPLooper(pcapIf.getDescription(), value, this.baseURL, packetCount);
            looper.start();

            this.threadPool.add(looper);
        }
    }

    public void stop() {
        for (PCAPLooper looper : this.threadPool) {
            if (looper.isAlive())
                looper.interrupt();
        }
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
        // pcap.loop(packetCount, jPacketHandelr, "jNetPcap");
    }
}
