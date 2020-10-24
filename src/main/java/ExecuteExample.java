import packet.PacketCapture;

public class ExecuteExample {

    public static void main(String[] args) throws Exception {
        String baseURL = "C:/Temp/packet_capture/";
        PacketCapture packetCapture = PacketCapture.getInstance(baseURL);
        packetCapture.findNetworkDevice();
        packetCapture.packetDumper(100);
    }
}
