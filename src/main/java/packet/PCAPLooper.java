package packet;


import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;

import java.text.SimpleDateFormat;

public class PCAPLooper extends Thread {
    private String name;
    private Pcap pcap;
    private String fullPath;
    private int packetCount = 100;

    public PCAPLooper(String name, Pcap pcap, String fullPath, int packetCount) {
        this.name = name;
        this.pcap = pcap;
        this.fullPath = fullPath;
        this.packetCount = packetCount;
    }

    @Override
    public void run() {
        PcapDumper dumper = null;
        try {
            while (true) {
                SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HHmmss");
                String dateTime = format.format(System.currentTimeMillis());

                String fileName = this.name + "-packet-" + dateTime + ".pcap";
                String filePath = fullPath + "/" + fileName;

                if (dumper != null)
                    dumper.close();

                dumper = pcap.dumpOpen(filePath);

                Dumper dumpHandler = new Dumper(dumper);

                pcap.loop(this.packetCount, dumpHandler, dumper);
            }
        } finally {
            if (dumper != null)
                dumper.close();
            pcap.close();
        }
    }
}
