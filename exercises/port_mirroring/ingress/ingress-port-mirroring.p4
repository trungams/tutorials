/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_IPV4      0x0800
#define IP_PROTOCOLS_TCP    6
#define HTTP_PORT           0x0050

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL         = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE  = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE   = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED      = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC         = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION    = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT       = 6;

const bit<32> I2E_CLONE_SESSION_ID = 5;
const bit<32> E2E_CLONE_SESSION_ID = 11;

#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)

struct intrinsic_metadata_t {
    bit<4>  mcast_grp;
    bit<4>  egress_rid;
    bit<16> mcast_hash;
    bit<32> lf_field_list;
}

/*
 * Headers
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgenPtr;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
}

struct metadata {
    intrinsic_metadata_t intrinsic_metadata;
}

/*
 * Parser
 */
parser MyParser (packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*
 * Checksum verification
 */
control MyVerifyChecksum (inout headers hdr, inout metadata meta) {
    apply {  }
}

/*
 * Ingress processing
 */
control MyIngress (inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
    action drop () {
        mark_to_drop(standard_metadata);
    }
    action set_nhop (bit<48> dmac, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action do_copy () {
        clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, {standard_metadata});
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
        default_action = drop();
    }
    table mirror_http_to_node {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            do_copy;
        }
        size = 256;
        default_action = do_copy();
    }
    table mirror_http_from_node {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            do_copy;
        }
        size = 256;
        default_action = do_copy();
    }

    apply {
        // forward all http traffic
        /*
        if (hdr.tcp.isValid()) {
            if (hdr.tcp.srcPort == HTTP_PORT)
                mirror_http_from_node.apply();
            if (hdr.tcp.dstPort == HTTP_PORT)
                mirror_http_to_node.apply();
        }
        */

        // selective mirroring: forward only tcp packets with length > 0
        if (hdr.tcp.isValid() 
            && ((bit<16>)hdr.ipv4.totalLen
                -(4*(bit<16>)hdr.ipv4.ihl)
                -(4*(bit<16>)hdr.tcp.dataOffset) > 0) )
        {
            if (hdr.tcp.srcPort == HTTP_PORT) {
                mirror_http_from_node.apply();
            }
            if (hdr.tcp.dstPort == HTTP_PORT) {
                mirror_http_to_node.apply();
            }
        }

        // ipv4 forwarding
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*
 * Egress processing
 */
control MyEgress (inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action mirror_to_port (bit<9> output_port) {
        standard_metadata.egress_spec = output_port;
    }

    table mirror_http {
        actions = {
            mirror_to_port;
        }
        size = 256;
    }

    apply { 
        if (IS_I2E_CLONE(standard_metadata)) {
            mirror_http.apply(); 
        }
    }
}

/*
 * Checksum computation
 */
control MyComputeChecksum (inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*
 * Deparser
 */
control MyDeparser (packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch (
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

