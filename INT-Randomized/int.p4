/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"
#include "include/checksum.p4"
#include "include/sink.p4"
#include "include/transit.p4"
#include "include/source.p4"
#include "include/forward.p4"

/********************************************************************
**************** I N G R E S S   P R O C E S S I N G ****************
********************************************************************/

control MyIngress(inout headers hdr, 
                    inout local_metadata_t local_metadata, 
                    inout standard_metadata_t standard_metadata) {

    apply {
        if (hdr.ipv4.isValid()) {

            // Perform L2 forwarding based on IPv4 destination address
            l3_forward.apply(hdr, local_metadata, standard_metadata);

            if (hdr.udp.isValid() || hdr.tcp.isValid()) {
                    
                // Setting source and sink local metadata
                process_int_source_sink.apply(hdr, local_metadata, standard_metadata);

                // In case of source add the INT header
                if (local_metadata.preserv_meta.source == true) {
                    bit<7> choose_mode;
                    random(choose_mode, 0, 99);
                    if (choose_mode == 0) {        
                        local_metadata.preserv_meta.int_mode = INT_MX;   // Set INT-MX with 1% probability
                    } else {     
                        local_metadata.preserv_meta.int_mode = INT_MD;   // Set INT-MD with 99% probability
                    }
                } else {
                    if (hdr.ipv4.dscp == DSCP_INT_MX) {
                        local_metadata.preserv_meta.int_mode = INT_MX;
                    } else if (hdr.ipv4.dscp == DSCP_INT_MD) {
                        local_metadata.preserv_meta.int_mode = INT_MD;
                    }
                }

                // Clone packet for Telemetry Report
                if (local_metadata.preserv_meta.int_mode == INT_MX || (local_metadata.preserv_meta.int_mode == INT_MD && local_metadata.preserv_meta.sink == true)) {
                    local_metadata.preserv_meta.ingress_port = standard_metadata.ingress_port;
                    local_metadata.preserv_meta.egress_port = standard_metadata.egress_port;
                    local_metadata.preserv_meta.deq_qdepth = standard_metadata.deq_qdepth;
                    local_metadata.preserv_meta.ingress_global_timestamp = standard_metadata.ingress_global_timestamp;
                    local_metadata.preserv_meta.l4_src_port = local_metadata.l4_src_port;
                    local_metadata.preserv_meta.l4_dst_port = local_metadata.l4_dst_port;
                    clone_preserving_field_list(CloneType.I2E, REPORT_MIRROR_SESSION_ID, 1);

                }
            } 
        }
    }
}

/********************************************************************
***************** E G R E S S   P R O C E S S I N G *****************
********************************************************************/

control MyEgress(inout headers hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    
    apply {

        if (local_metadata.preserv_meta.source == true) {
            process_int_source.apply(hdr, local_metadata);
        }

        // Insert original packet metadata into the cloned packet
        if (hdr.int_header.isValid() && standard_metadata.instance_type == CLONE) {
            standard_metadata.ingress_port = local_metadata.preserv_meta.ingress_port;
            standard_metadata.egress_port = local_metadata.preserv_meta.egress_port;
            standard_metadata.deq_qdepth = local_metadata.preserv_meta.deq_qdepth;
            standard_metadata.ingress_global_timestamp = local_metadata.preserv_meta.ingress_global_timestamp;
            local_metadata.l4_src_port = local_metadata.preserv_meta.l4_src_port;
            local_metadata.l4_dst_port = local_metadata.preserv_meta.l4_dst_port;
        }

        // Appending INT informations to the packet
        if (hdr.int_header.isValid() && ((hdr.ipv4.dscp == DSCP_INT_MD) || (hdr.ipv4.dscp == DSCP_INT_MX && standard_metadata.instance_type == CLONE))) {
            process_int_transit.apply(hdr, local_metadata, standard_metadata);
        }
        
        // In case of cloned packet, send telemetry report
        if (hdr.int_header.isValid() && standard_metadata.instance_type == CLONE) {
            process_int_report.apply(hdr, local_metadata, standard_metadata);
        }

        // In case of sink, remove INT header from original packet
        if (hdr.int_header.isValid() && local_metadata.preserv_meta.sink == true && standard_metadata.instance_type != CLONE) {
                process_int_sink.apply(hdr);
        }
    }
}

/***********************************************************
*********************** S W I T C H ************************
***********************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;