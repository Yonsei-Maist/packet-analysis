import packet.PacketCapture;

public class ExecuteExample {

    public static void main(String[] args) throws Exception {
        PacketCapture packetCapture = new PacketCapture();
        packetCapture.findNetworkDevice();
        packetCapture.packetOpen();
        packetCapture.packetDumper(100);
    }
}
