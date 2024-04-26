// This action sets the node as a INT source or INT sink in the ingress pipeline
control process_int_source_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action int_set_source () {
        local_metadata.preserv_meta.source = true;
    }

    action int_set_sink () {
        local_metadata.preserv_meta.sink = true;
    }

    table tb_set_source {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            int_set_source;
            NoAction();
        }
        const default_action = NoAction();
        size = MAX_PORTS;
    }

    table tb_set_sink {
        key = {
            standard_metadata.egress_port: exact;   
        }
        actions = {
            int_set_sink;
            NoAction();
        }
        const default_action = NoAction();
        size = MAX_PORTS;
    }

    apply {
        tb_set_source.apply();
        tb_set_sink.apply();
    }
}

// Insert INT header in the packet
control process_int_source (
    inout headers hdr,
    inout local_metadata_t local_metadata) {

    action int_source(bit<4> ins_mask0003, bit<4> ins_mask0407) {
        
        hdr.intl4_shim.setValid();                              // insert INT shim header
        if (local_metadata.preserv_meta.int_mode == INT_MD) {   // INT type: MD-type (1) , destination type (2), MX-type (3)
            hdr.intl4_shim.int_type = 1;                        
        } else{
            hdr.intl4_shim.int_type = 3;
        }
        hdr.intl4_shim.npt = 0;                                 // next protocol type: 0
        hdr.intl4_shim.len = 3;                                 // (INT_HEADER_SIZE >> 2)
        hdr.intl4_shim.original_dscp = hdr.ipv4.dscp;           // original DSCP

        hdr.int_header.setValid();
        hdr.int_header.ver = 2;                                 // INT 2.1
        hdr.int_header.d = 0;
        if (local_metadata.preserv_meta.int_mode == INT_MD) {
            hdr.int_header.remaining_hop_cnt = MAX_HOP_COUNT;
        }
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0;               // bit 8 is buffer related (not yet implemented), rest is reserved
        hdr.int_header.instruction_mask_1215 = 0;               // bit 15 is used for the checksum complement (not yet implemented), rest is reserved

        hdr.int_header.domain_specific_id = 0;                  // Unique INT Domain ID (not yet implemented)
        hdr.int_header.ds_instruction = 0;                      // Instruction bitmap specific to the INT Domain identified by the Domain specific ID (not yet implemented)
        hdr.int_header.ds_flags = 0;                            // Domain specific flags (not yet implemented)

        // Add the length of the INT header to the total length of the packet
        hdr.ipv4.len = hdr.ipv4.len + INT_TOTAL_HEADER_SIZE;
        if (local_metadata.preserv_meta.int_mode == INT_MD) {
            hdr.ipv4.dscp = DSCP_INT_MD;
        } else {
            hdr.ipv4.dscp = DSCP_INT_MX;
        }
        if (hdr.udp.isValid()) {
            hdr.udp.len = hdr.udp.len + INT_TOTAL_HEADER_SIZE;
        }
    }

    table tb_int_source {
        key = {
            // Instruction bitmap based on the IPv4 destination address
            // But could be also based on packet flows
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            int_source;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        tb_int_source.apply();
    }
}