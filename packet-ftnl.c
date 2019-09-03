/* packet-ncsi.c
 * Routines for Brocade 78xx FTNL FCIP protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * By Christian Svensson <blue@cmd.nu>
 * Copyright 2019 Christian Svensson
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/etypes.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_register_ftnl(void);

static int proto_ftnl = -1;

static gint ett_ftnl = -1;
static gint ett_ftnl_cmd = -1;

static dissector_handle_t ftnl_handle;
static dissector_handle_t fc_handle;

#define MINIMAL_FRAME_HEADER_LEN 8


/* This method dissects fully reassembled messages */
static int
dissect_ftnl_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  guint32 offset = 0;
  guint32 pdulen;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTNL");
  col_clear(pinfo->cinfo, COL_INFO);

  pdulen = tvb_get_ntohs (tvb, 6);
  proto_item *ti = proto_tree_add_item(tree, proto_ftnl, tvb, 0, pdulen, ENC_NA);
  proto_tree *ftnl_tree = proto_item_add_subtree(ti, ett_ftnl);
  ftnl_tree++;
 
  offset += pdulen;
  return offset;
}

static guint
get_ftnl_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint)tvb_get_ntohs(tvb, offset+6);
}

/* Handle TCP segment reassembly for messages/PDUs */
static int
dissect_ftnl(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MINIMAL_FRAME_HEADER_LEN,
      get_ftnl_pdu_len, dissect_ftnl_pdu, data);

  return tvb_captured_length(tvb);
}

void
proto_register_ftnl(void)
{
  static hf_register_info hf[] = {
#if 0
    { &hf_ncsi_mc_id,
      { "MC ID", "ncsi.mc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_header_rev,
      { "Header Revision", "ncsi.hdr_rev", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_iid,
      { "Instance ID", "ncsi.iid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_ctrl_pkt_type,
      { "Control Packet Type", "ncsi.ctrl_pkt_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_ch_id,
      { "Channel ID", "ncsi.ch_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_payload_len,
      { "Payload Length", "ncsi.payload_len", FT_UINT16, BASE_DEC, NULL, 0xfff, NULL, HFILL }
    },
    { &hf_ncsi_cmd_response,
      { "Response Code", "ncsi.response", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_cmd_reason,
      { "Reason Code", "ncsi.reason", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_cmd_oem_req,
      { "OEM Request", "ncsi.oem_req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_cmd_oem_resp,
      { "OEM Response", "ncsi.oem_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_oem_mid,
      { "Manufacturer ID", "ncsi.oem.mid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_oem_vdata,
      { "Vendor data", "ncsi.oem.vendor_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
#endif
  };

  static gint *ett[] = {&ett_ftnl, &ett_ftnl_cmd};

  static ei_register_info ei[] = {
#if 0
     { &ei_ncsi_cmd_unknown, { "ncsi.cmd_unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
#endif
  };

  proto_ftnl = proto_register_protocol("Brocade 78xx FCIP Tunnel", "FTNL", "ftnl");
  proto_register_field_array(proto_ftnl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_module_t* expert_ftnl;
  expert_ftnl = expert_register_protocol(proto_ftnl);
  expert_register_field_array(expert_ftnl, ei, array_length(ei));
}

/* This is called for those sessions where we have explicitly said
   this to be FTNL using "Decode As..."
*/
static int
dissect_ftnl_handle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  gint bytes_remaining = tvb_captured_length (tvb);
  guint32 marker;

  if (bytes_remaining < 20) {
    return FALSE;
  }

  marker = tvb_get_ntohl (tvb, 0);
  if (marker != 0x46544e4c) {
    return FALSE;
  }

  return dissect_ftnl(tvb, pinfo, tree, data);
}

static gboolean
dissect_ftnl_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
  gint bytes_remaining = tvb_captured_length (tvb);
  guint32 marker;

  if (bytes_remaining < 20) {
    return FALSE;
  }

  if (pinfo->srcport != 3225 && pinfo->destport != 3225) {
    return FALSE;
  }

  marker = tvb_get_ntohl (tvb, 0);
  if (marker != 0x46544e4c) {
    return FALSE;
  }

  dissect_ftnl(tvb, pinfo, tree, data);

  return (TRUE);
}

void
proto_reg_handoff_ftnl(void)
{
  heur_dissector_add("tcp", dissect_ftnl_heur, "Brocade 78xx FCIP ", "ftnl_tcp", proto_ftnl, HEURISTIC_ENABLE);
  ftnl_handle = create_dissector_handle(dissect_ftnl_handle, proto_ftnl);
  dissector_add_for_decode_as_with_preference("tcp.port", ftnl_handle);
  fc_handle = find_dissector_add_dependency("fc", proto_ftnl);
}
