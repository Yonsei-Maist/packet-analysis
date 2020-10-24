package packet;

import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Dumper implements PcapPacketHandler<PcapDumper> {
    private PcapDumper mainDumper;

    public Dumper(PcapDumper mainDumper) {
        this.mainDumper = mainDumper;
    }

    @Override
    public void nextPacket(PcapPacket pcapPacket, PcapDumper pcapDumper) {
        this.mainDumper.dump(pcapPacket);
    }
}