// Synthetic Link Layer used by Mac OS X
// http://www.tcpdump.org/linktypes/LINKTYPE_PKTAP.html

var NullPacket = require("./null_packet");
var EthernetPacket = require("./ethernet_packet");
var RadioPacket = require("./ieee802.11/radio_packet");

function PKTapPacket (emitter) {
    this.emitter = emitter;

    this.pktap_header_len = null;
    this.record_type = null;
    this.dlt_value = null;
    this.interface_name = null;
    this.flags = null;
    this.protocol_family = null;
    this.link_layer_header_len = null;
    this.link_layer_trailer_len = null;
    this.process_id = null;
    this.command_name = null;
    this.service_class = null;
    this.interface_type = null;
    this.unit_number_of_interfaces = null;
    this.effective_process_id = null;
    this.effective_command_name = null;
    this.extra_data = null;

    this.payload = null;
}

PKTapPacket.prototype.decode = function (raw_packet, offset) {
    this.pktap_header_len = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.record_type = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.dlt_value = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.interface_name = raw_packet.toString('ascii', offset, 24);
    offset += 24;
    
    this.flags = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.protocol_family = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.link_layer_header_len = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.link_layer_trailer_len = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.process_id = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.command_name = raw_packet.toString('ascii', offset, 20);
    offset += 20;
    
    this.service_class = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.interface_type = raw_packet.readUInt16LE(offset);
    offset += 2;
    
    this.unit_number_of_interfaces = raw_packet.readUInt16LE(offset);
    offset += 2;
    
    this.effective_process_id = raw_packet.readUInt32LE(offset);
    offset += 4;
    
    this.effective_command_name = raw_packet.toString('ascii', offset, 20);
    offset += 20;
    
    this.extra_data = raw_packet.slice(offset, this.pktap_header_len - offset);
    
    this.interface_name = this.interface_name.substr(0, this.interface_name.indexOf('\0'));
    this.command_name = this.command_name.substr(0, this.command_name.indexOf('\0'));
    this.effective_command_name = this.effective_command_name.substr(0, this.effective_command_name.indexOf('\0'));
    
    // TODO: This code needs to be centralised and generalised so that many
    // type of link layer parsers can register. Similar code is also used in
    // pcap_packet.js as well.
    
    // DLT_NULL; LINKTYPE_NULL=0
    // DLT_EN10MB; LINKTYPE_ETHERNET=1
    // DLT_IEEE802; LINKTYPE_TOKEN_RING=6
    // DLT_ARCNET; LINKTYPE_ARCNET=7
    // DLT_SLIP; LINKTYPE_SLIP=8
    
    switch (this.dlt_value) {
    case 0:
        this.payload = new NullPacket(this.emitter).decode(raw_packet, this.pktap_header_len);
        
        break;
        
    case 1:
        this.payload = new EthernetPacket(this.emitter).decode(raw_packet, this.pktap_header_len);

        break;

    case 6:
        this.payload = new RadioPacket(this.emitter).decode(raw_packet, this.pktap_header_len);
        
        break;
        
    default:
        console.log("node_pcap: PKTapPacket() - Don't know how to decode dlt_value", this.dlt_value);
    }

    return this;
};

PKTapPacket.prototype.decoderName = "pktap-packet";
PKTapPacket.prototype.eventsOnDecode = false;

PKTapPacket.prototype.toString = function () {
    var ret = "";

    // switch (this.packet_type) {
    // case 0:
    //     ret += "recv_us";
    //     break;
    // case 1:
    //     ret += "broadcast";
    //     break;
    // case 2:
    //     ret += "multicast";
    //     break;
    // case 3:
    //     ret += "remote_remote";
    //     break;
    // case 4:
    //     ret += "sent_us";
    //     break;
    // }
    //
    // ret += " addrtype " + this.address_type;
    //
    // ret += " " + this.address;
    //
    // switch (this.ethertype) {
    // case 0x800:
    //     ret += " IPv4";
    //     break;
    // case 0x806:
    //     ret += " ARP";
    //     break;
    // case 0x86dd:
    //     ret += " IPv6";
    //     break;
    // case 0x88cc:
    //     ret += " LLDP";
    //     break;
    // default:
    //     ret += " ethertype " + this.ethertype;
    // }

    return ret + " " + this.payload.toString();
};

module.exports = PKTapPacket;
