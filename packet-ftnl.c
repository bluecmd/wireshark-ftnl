/* packet-ftnl.c
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
#include "packet-fc.h"
#include "packet-tcp.h"

void proto_register_ftnl(void);

static int proto_ftnl = -1;

static int hf_ftnl_header_len = -1;
static int hf_ftnl_cmd = -1;
static int hf_ftnl_frame_len = -1;
static int hf_ftnl_frame_seq = -1;
static int hf_ftnl_ack_seq = -1;
static int hf_ftnl_tag = -1;
static int hf_ftnl_header_crc = -1;
static int hf_ftnl_header_crc_status = -1;
static int hf_ftnl_data_crc = -1;
static int hf_ftnl_data_crc_status = -1;
static int hf_ftnl_cmd_bind_req = -1;
static int hf_ftnl_cmd_bind_resp = -1;
static int hf_ftnl_cmd_keepalive = -1;
static int hf_ftnl_cmd_window = -1;
static int hf_ftnl_data = -1;
static int hf_ftnl_data_marker = -1;
static int hf_ftnl_data_frame_cnt = -1;
static int hf_ftnl_data_unknown1 = -1;
static int hf_ftnl_data_frame_len = -1;
static int hf_ftnl_data_batch_len1 = -1;
static int hf_ftnl_data_batch_len2 = -1;
static int hf_ftnl_data_batch_header = -1;
static int hf_ftnl_data_wire_header = -1;
static int hf_ftnl_data_inner_crc = -1;
static int hf_ftnl_data_inner_crc_status = -1;

static gint ett_ftnl = -1;

static expert_field ei_ftnl_cmd_unknown = EI_INIT;
static expert_field ei_ftnl_wrong_hdr_crc = EI_INIT;
static expert_field ei_ftnl_wrong_data_crc = EI_INIT;
static expert_field ei_ftnl_wrong_inner_data_crc = EI_INIT;

static dissector_handle_t ftnl_handle;
static dissector_handle_t fc_handle;

static dissector_table_t ftnl_cmd_table;

#define MINIMAL_FRAME_HEADER_LEN 8

static const guint crc16_precompiled_A001[256] =
{
  0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
  0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
  0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
  0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
  0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
  0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
  0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
  0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
  0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
  0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
  0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
  0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
  0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
  0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
  0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
  0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
  0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
  0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
  0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
  0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
  0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
  0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
  0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
  0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
  0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
  0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
  0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
  0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
  0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
  0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
  0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
  0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
};

/* copied from wsutil/crc16.c in wireshark */
static guint16 crc16_reflected(const guint8 *buf, guint len,
    guint16 crc_in, const guint table[])
{
  guint crc16 = (guint)crc_in;

  while( len-- != 0 )
    crc16 = table[(crc16 ^ *buf++) & 0xff] ^ (crc16 >> 8);

  return (guint16)crc16;
}

guint16
crc16_ftnl_tvb_offset(tvbuff_t *tvb, guint offset, guint len)
{
  const guint8 *buf;
  tvb_ensure_bytes_exist(tvb, offset, len);
  buf = tvb_get_ptr(tvb, offset, len);
  return crc16_reflected(buf, len, 0xffff, crc16_precompiled_A001);
}

// Max size is 14 static header, 15 frame sizes, 2 byte crc, and 2 byte align
#define MAX_DATA_HEADER_SIZE (14+2*15+2+2)

static int
dissect_ftnl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint32 offset = 0;
  guint32 cnt = 0;
  guint32 lens[15];
#if 0
  guint8 hdrnocrc[MAX_DATA_HEADER_SIZE];
  guint16 crc;
#endif
  tvbuff_t *next_tvb;
  col_append_str(pinfo->cinfo, COL_INFO, "Data");
  ti = proto_tree_add_item(tree, hf_ftnl_data, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ftnl);

  proto_tree_add_item(tree, hf_ftnl_data_marker, tvb, 0, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(tree, hf_ftnl_data_frame_cnt, tvb, 4, 1, ENC_BIG_ENDIAN, &cnt);
  proto_tree_add_item(tree, hf_ftnl_data_unknown1, tvb, 4, 10, ENC_BIG_ENDIAN);
  offset += 14;
  for (guint32 i = 0; i < cnt; i++) {
    proto_tree_add_item_ret_uint(tree, hf_ftnl_data_frame_len, tvb, offset, 2, ENC_BIG_ENDIAN, &lens[i]);
    offset += 2;
  }

#if 0
  tvb_memcpy(tvb, hdrnocrc, 0, offset+4);
  memset(hdrnocrc + offset, 0, 2);
  crc = crc16_reflected(hdrnocrc, offset+4, 0xffff, crc16_precompiled_A001);
#endif
  proto_tree_add_checksum(tree, tvb, offset, hf_ftnl_data_inner_crc,
      hf_ftnl_data_inner_crc_status, &ei_ftnl_wrong_inner_data_crc, pinfo,
      /*crc*/ 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
  offset += 2;
  if (cnt % 2 == 1) {
    // Align to 4 bytes
    offset += 2;
  }

  // Four types of known data type:
  // E - One frame
  // F
  // H
  // K - Batched
  //guint8 variant = tvb_get_guint8(tvb, 3);

  for (guint32 i = 0; i < cnt; i++) {
    proto_tree *f_tree = proto_item_add_subtree(ti, ett_ftnl);
    proto_tree_add_item(f_tree, hf_ftnl_data_wire_header, tvb, offset, 0x14, ENC_BIG_ENDIAN);
    offset += 0x14;
    fc_data_t fc_data;
    fc_data.sof_eof = 0;
    guint32 fclen = lens[i] - 0x14;
    next_tvb = tvb_new_subset_length(tvb, offset, fclen);
    call_dissector_with_data(fc_handle, next_tvb, pinfo, f_tree, &fc_data);
    offset += fclen;
  }
  return offset;
}

/* This method dissects fully reassembled messages */
static int
dissect_ftnl_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint32 hdrlen = 0;
  guint32 offset = 0;
  guint32 cmd = 0;
  guint32 pdulen = 0;
  guint16 crc = 0;
  guint8 hdrnocrc[24];

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTNL");
  col_clear(pinfo->cinfo, COL_INFO);

  pdulen = tvb_get_ntohs (tvb, 6);
  proto_item *ti = proto_tree_add_item(tree, proto_ftnl, tvb, 0, pdulen, ENC_NA);
  proto_tree *ftnl_tree = proto_item_add_subtree(ti, ett_ftnl);

  proto_tree_add_item_ret_uint(ftnl_tree, hf_ftnl_header_len, tvb, 4, 1, ENC_BIG_ENDIAN, &hdrlen);
  proto_tree_add_item_ret_uint(ftnl_tree, hf_ftnl_cmd, tvb, 5, 1, ENC_BIG_ENDIAN, &cmd);
  proto_tree_add_item(ftnl_tree, hf_ftnl_frame_len, tvb, 6, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(ftnl_tree, hf_ftnl_frame_seq, tvb, 8, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(ftnl_tree, hf_ftnl_ack_seq, tvb, 12, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(ftnl_tree, hf_ftnl_tag, tvb, 16, 4, ENC_BIG_ENDIAN);
  offset += 20;

  // Mask the header CRC for the CRC computation
  tvb_memcpy(tvb, hdrnocrc, 0, 24);
  memset(hdrnocrc + offset, 0, 2);
  crc = crc16_reflected(hdrnocrc, 24, 0xffff, crc16_precompiled_A001);

  proto_tree_add_checksum(ftnl_tree, tvb, offset, hf_ftnl_header_crc,
      hf_ftnl_header_crc_status, &ei_ftnl_wrong_hdr_crc, pinfo,
      crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
  offset += 2;
  crc = tvb_get_ntohs (tvb, offset);
  if (crc != 0) {
    crc = crc16_ftnl_tvb_offset(tvb, offset+2, pdulen - (offset+2));
  }
  proto_tree_add_checksum(ftnl_tree, tvb, offset, hf_ftnl_data_crc,
      hf_ftnl_data_crc_status, &ei_ftnl_wrong_data_crc, pinfo,
      crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
  offset += 2;

  if (hdrlen == 20) {
    dissector_handle_t cmd_handle = dissector_get_uint_handle(ftnl_cmd_table, cmd);
    if (cmd_handle != NULL) {
      proto_tree *cmd_tree = proto_item_add_subtree(ti, ett_ftnl);
      tvbuff_t *tvb_cmd = tvb_new_subset_length(tvb, offset, pdulen - offset);
      offset += call_dissector(cmd_handle, tvb_cmd, pinfo, cmd_tree);
    } else {
      col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "[unknown command]");
      expert_add_info(pinfo, ti, &ei_ftnl_cmd_unknown);
    }
  }

  if (hdrlen == 24) {
    proto_tree *data_tree = proto_item_add_subtree(ti, ett_ftnl);
    tvbuff_t *tvb_data = tvb_new_subset_remaining(tvb, offset);
    dissect_ftnl_data(tvb_data, pinfo, data_tree);
  }
 
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
dissect_ftnl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MINIMAL_FRAME_HEADER_LEN,
      get_ftnl_pdu_len, dissect_ftnl_pdu, data);

  return tvb_captured_length(tvb);
}

void
proto_register_ftnl(void)
{
  static hf_register_info hf[] = {
    { &hf_ftnl_header_len,
      { "Header Length", "ftnl.hdrlen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_cmd,
      { "Command", "ftnl.cmd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_frame_len,
      { "Frame Length", "ftnl.framelen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_frame_seq,
      { "Frame Sequence", "ftnl.frameseq", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_ack_seq,
      { "Ack Sequence", "ftnl.ackseq", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_tag,
      { "Tag", "ftnl.tag", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_header_crc,
      { "Header CRC", "ftnl.hdrcrc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_header_crc_status,
      { "Header CRC Status", "ftnl.hdrcrc.status", FT_UINT8, BASE_NONE,
        VALS(proto_checksum_vals), 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_crc,
      { "Payload CRC", "ftnl.datacrc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_crc_status,
      { "Payload CRC Status", "ftnl.datacrc.status", FT_UINT8, BASE_NONE,
        VALS(proto_checksum_vals), 0x0, NULL, HFILL }
    },
    { &hf_ftnl_cmd_bind_req,
      { "Bind Request", "ftnl.bind.req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_cmd_bind_resp,
      { "Bind Response", "ftnl.bind.resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_cmd_keepalive,
      { "Keepalive", "ftnl.keepalive", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_cmd_window,
      { "Window Update", "ftnl.window", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data,
      { "Data", "ftnl.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_marker,
      { "Marker", "ftnl.data.marker", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_frame_cnt,
      { "No. of frames", "ftnl.data.cnt", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
    },
    { &hf_ftnl_data_unknown1,
      { "Unknown1", "ftnl.data.unknown1", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_batch_len1,
      { "Batch Length #1", "ftnl.data.blen1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_batch_len2,
      { "Batch Length #2", "ftnl.data.blen2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_batch_header,
      { "Batch Header", "ftnl.data.bhdr", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_wire_header,
      { "FC Wire Header", "ftnl.data.wirehdr", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_frame_len,
      { "Frame Length", "ftnl.data.framelen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ftnl_data_inner_crc,
      { "Data Frame CRC", "ftnl.data.crc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
  };

  static gint *ett[] = {&ett_ftnl};

  static ei_register_info ei[] = {
     { &ei_ftnl_cmd_unknown, { "ftnl.cmd.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
     { &ei_ftnl_wrong_hdr_crc, { "ftnl.hdrcrc.wrong", PI_PROTOCOL, PI_WARN, "Header CRC wrong", EXPFILL }},
     { &ei_ftnl_wrong_data_crc, { "ftnl.datacrc.wrong", PI_PROTOCOL, PI_WARN, "Data CRC wrong", EXPFILL }},
     { &ei_ftnl_wrong_inner_data_crc, { "ftnl.data.crc.wrong", PI_PROTOCOL, PI_WARN, "Inner Data CRC wrong", EXPFILL }},
  };

  proto_ftnl = proto_register_protocol("Brocade 78xx FCIP Tunnel", "FTNL", "ftnl");
  proto_register_field_array(proto_ftnl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_module_t* expert_ftnl;
  expert_ftnl = expert_register_protocol(proto_ftnl);
  expert_register_field_array(expert_ftnl, ei, array_length(ei));

  ftnl_cmd_table = register_dissector_table("ftnl.cmd", "Command", proto_ftnl, FT_UINT8, BASE_NONE);
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
dissect_ftnl_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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

static int
dissect_ftnl_bind_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  col_append_str(pinfo->cinfo, COL_INFO, "Bind Request");
  ti = proto_tree_add_item(tree, hf_ftnl_cmd_bind_req, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ftnl);
  tree++;

  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ftnl_bind_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  col_append_str(pinfo->cinfo, COL_INFO, "Bind Response");
  ti = proto_tree_add_item(tree, hf_ftnl_cmd_bind_resp, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ftnl);
  tree++;
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ftnl_keepalive(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  col_append_str(pinfo->cinfo, COL_INFO, "Keepalive");
  ti = proto_tree_add_item(tree, hf_ftnl_cmd_keepalive, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ftnl);
  tree++;
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ftnl_window(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  col_append_str(pinfo->cinfo, COL_INFO, "Window Update");
  ti = proto_tree_add_item(tree, hf_ftnl_cmd_window, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ftnl);
  tree++;
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

void
proto_reg_handoff_ftnl(void)
{
  heur_dissector_add("tcp", dissect_ftnl_heur, "Brocade 78xx FCIP ", "ftnl_tcp", proto_ftnl, HEURISTIC_ENABLE);
  ftnl_handle = create_dissector_handle(dissect_ftnl_handle, proto_ftnl);
  dissector_add_for_decode_as_with_preference("tcp.port", ftnl_handle);
  fc_handle = find_dissector_add_dependency("fc", proto_ftnl);

  dissector_add_uint("ftnl.cmd", 1, create_dissector_handle(dissect_ftnl_bind_req, proto_ftnl));
  dissector_add_uint("ftnl.cmd", 2, create_dissector_handle(dissect_ftnl_bind_resp, proto_ftnl));
  dissector_add_uint("ftnl.cmd", 4, create_dissector_handle(dissect_ftnl_keepalive, proto_ftnl));
  dissector_add_uint("ftnl.cmd", 5, create_dissector_handle(dissect_ftnl_window, proto_ftnl));
}
