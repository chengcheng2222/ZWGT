from pathlib import Path

OUT = Path("inputs_explicit")
OUT.mkdir(exist_ok=True)

def le16(x): return int(x).to_bytes(2, "little", signed=False)
def le32(x): return int(x).to_bytes(4, "little", signed=False)

def encap(cmd, payload=b"", session=0, status=0, sender_ctx=b"\x00"*8, options=0):
    return (
        le16(cmd) +
        le16(len(payload)) +
        le32(session) +
        le32(status) +
        sender_ctx +
        le32(options) +
        payload
    )

def reg_session():
    return encap(0x0065, le16(1) + le16(0), session=0)

def list_services():
    return encap(0x0004, b"", session=0)

def list_identity():
    return encap(0x0063, b"", session=0)

def list_interfaces():
    return encap(0x0064, b"", session=0)

def mr(service, path, data=b""):
    assert len(path) % 2 == 0
    return bytes([service, len(path) // 2]) + path + data

def p_cls_inst(cls_id, inst_id):
    return bytes([0x20, cls_id, 0x24, inst_id])

def p_cls_inst_attr(cls_id, inst_id, attr_id):
    return bytes([0x20, cls_id, 0x24, inst_id, 0x30, attr_id])

def cpf_ucmm(mr_payload):
    return (
        le32(0) +              # Interface Handle
        le16(0) +              # Timeout
        le16(2) +              # Item Count
        le16(0x0000) + le16(0) +                    # Null Address Item
        le16(0x00B2) + le16(len(mr_payload)) + mr_payload  # UCMM Data Item
    )

def send_rr(session_handle, mr_payload):
    return encap(0x006F, cpf_ucmm(mr_payload), session=session_handle)

def file_content(frames):
    out = bytearray()
    for f in frames:
        out += le32(len(f))
        out += f
    return bytes(out)

def write_seed(name, frames):
    (OUT / name).write_bytes(file_content(frames))

ASM_154 = p_cls_inst(0x04, 0x9A)
ASM_154_A3 = p_cls_inst_attr(0x04, 0x9A, 0x03)
ASM_154_A4 = p_cls_inst_attr(0x04, 0x9A, 0x04)

IDENTITY_1_A1 = p_cls_inst_attr(0x01, 0x01, 0x01)
IDENTITY_1_A7 = p_cls_inst_attr(0x01, 0x01, 0x07)

TCPIP_1_A1 = p_cls_inst_attr(0xF5, 0x01, 0x01)
TCPIP_1_A5 = p_cls_inst_attr(0xF5, 0x01, 0x05)

ETHLINK_1_A3 = p_cls_inst_attr(0xF6, 0x01, 0x03)
CONNMGR_1_A1 = p_cls_inst_attr(0x06, 0x01, 0x01)

sess1 = 1

write_seed("01_register_only.bin", [
    reg_session(),
])

write_seed("02_list_services.bin", [
    list_services(),
])

write_seed("03_list_identity.bin", [
    list_identity(),
])

write_seed("04_list_interfaces.bin", [
    list_interfaces(),
])

write_seed("05_reg_get_asm154_attr3.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, ASM_154_A3)),
])

write_seed("06_reg_get_asm154_attr4.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, ASM_154_A4)),
])

write_seed("07_reg_getall_asm154.bin", [
    reg_session(),
    send_rr(sess1, mr(0x01, ASM_154)),
])

write_seed("08_reg_set_asm154_attr3_zero128.bin", [
    reg_session(),
    send_rr(sess1, mr(0x10, ASM_154_A3, b"\x00" * 128)),
])

write_seed("09_reg_set_asm154_attr3_ff128.bin", [
    reg_session(),
    send_rr(sess1, mr(0x10, ASM_154_A3, b"\xFF" * 128)),
])

write_seed("10_reg_set_asm154_attr3_ramp128.bin", [
    reg_session(),
    send_rr(sess1, mr(0x10, ASM_154_A3, bytes(range(128)))),
])

write_seed("11_reg_set_asm154_attr3_short127.bin", [
    reg_session(),
    send_rr(sess1, mr(0x10, ASM_154_A3, b"\x41" * 127)),
])

write_seed("12_reg_set_asm154_attr3_long129.bin", [
    reg_session(),
    send_rr(sess1, mr(0x10, ASM_154_A3, b"\x42" * 129)),
])

write_seed("13_reg_get_identity_attr1.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, IDENTITY_1_A1)),
])

write_seed("14_reg_get_identity_attr7.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, IDENTITY_1_A7)),
])

write_seed("15_reg_get_tcpip_attr1.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, TCPIP_1_A1)),
])

write_seed("16_reg_get_tcpip_attr5.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, TCPIP_1_A5)),
])

write_seed("17_reg_get_ethlink_attr3.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, ETHLINK_1_A3)),
])

write_seed("18_reg_get_connmgr_attr1.bin", [
    reg_session(),
    send_rr(sess1, mr(0x0E, CONNMGR_1_A1)),
])

write_seed("19_reg_bad_service_asm154.bin", [
    reg_session(),
    send_rr(sess1, mr(0x4E, ASM_154)),
])

write_seed("20_reg_class_only_path.bin", [
    reg_session(),
    send_rr(sess1, mr(0x01, b"\x20\x04")),
])

EXPLICIT_DICT = r'''
encap_nop="\x00\x00"
encap_list_services="\x04\x00"
encap_list_identity="\x63\x00"
encap_list_interfaces="\x64\x00"
encap_register_session="\x65\x00"
encap_unregister_session="\x66\x00"
encap_send_rr_data="\x6f\x00"
encap_send_unit_data="\x70\x00"

encap_len_0="\x00\x00"
encap_len_4="\x04\x00"
encap_len_10="\x0a\x00"
encap_len_16="\x10\x00"
encap_len_24="\x18\x00"
encap_len_32="\x20\x00"

proto_version_1="\x01\x00"
session_0="\x00\x00\x00\x00"
session_1="\x01\x00\x00\x00"
session_ff="\xff\xff\xff\xff"
status_0="\x00\x00\x00\x00"

if_handle_0="\x00\x00\x00\x00"
timeout_0="\x00\x00"
itemcount_2="\x02\x00"

cpf_null_addr="\x00\x00\x00\x00"
cpf_ucmm_item="\xb2\x00"
cpf_connected_item="\xb1\x00"
cpf_conn_addr="\xa1\x00"
cpf_seq_addr="\x02\x80"

svc_get_attr_all="\x01"
svc_get_attr_single="\x0e"
svc_set_attr_single="\x10"
svc_reset="\x05"
svc_multiple_service_packet="\x0a"
svc_forward_open="\x54"
svc_large_forward_open="\x5b"
svc_forward_close="\x4e"
svc_unconnected_send="\x52"

seg_class_identity="\x20\x01"
seg_class_mr="\x20\x02"
seg_class_assembly="\x20\x04"
seg_class_connmgr="\x20\x06"
seg_class_tcpip="\x20\xf5"
seg_class_ethlink="\x20\xf6"

seg_inst_1="\x24\x01"
seg_inst_100="\x24\x64"
seg_inst_150="\x24\x96"
seg_inst_151="\x24\x97"
seg_inst_152="\x24\x98"
seg_inst_153="\x24\x99"
seg_inst_154="\x24\x9a"

seg_connpt_100="\x2c\x64"
seg_connpt_150="\x2c\x96"
seg_connpt_152="\x2c\x98"
seg_connpt_153="\x2c\x99"

seg_attr_1="\x30\x01"
seg_attr_3="\x30\x03"
seg_attr_4="\x30\x04"
seg_attr_5="\x30\x05"
seg_attr_7="\x30\x07"

path_asm154="\x20\x04\x24\x9a"
path_asm154_attr3="\x20\x04\x24\x9a\x30\x03"
path_asm154_attr4="\x20\x04\x24\x9a\x30\x04"
path_identity1="\x20\x01\x24\x01"
path_identity1_attr1="\x20\x01\x24\x01\x30\x01"
path_identity1_attr7="\x20\x01\x24\x01\x30\x07"
path_tcpip1="\x20\xf5\x24\x01"
path_tcpip1_attr1="\x20\xf5\x24\x01\x30\x01"
path_tcpip1_attr5="\x20\xf5\x24\x01\x30\x05"
path_ethlink1="\x20\xf6\x24\x01"
path_ethlink1_attr3="\x20\xf6\x24\x01\x30\x03"
path_connmgr1="\x20\x06\x24\x01"
path_connmgr1_attr1="\x20\x06\x24\x01\x30\x01"

fo_path_owner_cfg="\x20\x04\x24\x97\x2c\x96\x2c\x64"
fo_path_owner_nocfg="\x20\x04\x2c\x96\x2c\x64"
fo_path_input_only="\x20\x04\x24\x97\x2c\x98\x2c\x64"
fo_path_listen_only="\x20\x04\x24\x97\x2c\x99\x2c\x64"

conn_serial_1337="\x37\x13"
vendor_1111="\x11\x11"
originator_serial_22222222="\x22\x22\x22\x22"
ot_cid_12345678="\x78\x56\x34\x12"
to_cid_87654321="\x21\x43\x65\x87"
rpi_100ms="\xa0\x86\x01\x00"
transport_cyclic_server="\xa3"

size_127="\x7f"
size_128="\x80"
size_129="\x81"
'''

Path("cipster_explicit.dict").write_text(EXPLICIT_DICT.strip() + "\n", encoding="utf-8")
print("generated inputs_explicit/ and cipster_explicit.dict")
