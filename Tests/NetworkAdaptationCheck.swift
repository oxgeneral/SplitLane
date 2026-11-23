import Foundation

enum NetworkAdaptationCheck {
    static func run() {
        let wifi = """
        en0: flags=8863<UP,BROADCAST> mtu 1500
            inet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
            inet6 2001:db8::10 prefixlen 64
            inet6 fe80::1%en0 prefixlen 64 scopeid 0x5
        """
        let vpn = """
        utun4: flags=8051<UP,POINTOPOINT> mtu 1500
            inet 198.18.0.1 --> 198.18.0.1 netmask 0xffff0000
        """
        let initial = PacketRoutingConfiguration.addressSnapshot(in: wifi + "\n" + vpn)
        precondition(initial.count == 4)
        precondition(initial == PacketRoutingConfiguration.addressSnapshot(in: vpn + "\n" + wifi))
        precondition(initial == PacketRoutingConfiguration.addressSnapshot(in: (wifi + "\n" + vpn)
            .replacingOccurrences(of: "mtu 1500", with: "mtu 1400")))
        for changed in [
            wifi.replacingOccurrences(of: "192.0.2.10", with: "192.0.2.11") + "\n" + vpn,
            wifi.replacingOccurrences(of: "2001:db8::10", with: "2001:db8::11") + "\n" + vpn,
            wifi + "\n" + vpn.replacingOccurrences(of: "utun4", with: "utun5"),
            wifi
        ] {
            precondition(initial != PacketRoutingConfiguration.addressSnapshot(in: changed))
        }
    }
}
