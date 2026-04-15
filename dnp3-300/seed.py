#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate a high-quality AFL seed corpus and dictionary for the modified
opendnp3 3.0.0 cpp/examples/outstation/main.cpp harness.

Target assumptions (match the example / your modified harness):
- Outstation link LocalAddr = 10
- Master link RemoteAddr = 1
- TCP transport, real DNP3 link/transport/application stack
- SuccessCommandHandler::Create() is used
- DatabaseConfig(10): 10 points per default type

Outputs:
- ./seeds_valid/
- ./seeds_boundary/
- ./opendnp3_outstation.dict
"""

from pathlib import Path
import struct


def crc16_dnp(data: bytes) -> int:
    """
    CRC-16/DNP:
      width=16 poly=0x3D65 init=0x0000 refin=true refout=true xorout=0xFFFF
    Implemented in reflected form with poly 0xA6BC.
    """
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc ^ 0xFFFF


def crc_le(data: bytes) -> bytes:
    c = crc16_dnp(data)
    return bytes((c & 0xFF, (c >> 8) & 0xFF))


def dnp3_frame(user: bytes, dest: int = 10, src: int = 1, link_ctrl: int = 0xD3) -> bytes:
    """
    Build one DNP3 link frame.
    Default link_ctrl=0xD3 => confirmed user data, master->outstation, FCB=0.
    """
    length = 5 + len(user)  # ctrl + dst(2) + src(2) + user, CRCs not counted
    hdr_wo_crc = bytes([
        0x05, 0x64,
        length & 0xFF,
        link_ctrl & 0xFF,
        dest & 0xFF, (dest >> 8) & 0xFF,
        src & 0xFF, (src >> 8) & 0xFF
    ])

    out = bytearray(hdr_wo_crc)
    out += crc_le(hdr_wo_crc)

    for i in range(0, len(user), 16):
        chunk = user[i:i + 16]
        out += chunk
        out += crc_le(chunk)

    return bytes(out)


def app_user(tp: int = 0xC0, app_ctrl: int = 0xC0, func: int = 0x01, body: bytes = b"") -> bytes:
    """
    Single-fragment transport + app header.
    tp=0xC0 => FIR|FIN, seq=0
    app_ctrl=0xC0 => FIR|FIN, seq=0
    """
    return bytes([tp & 0xFF, app_ctrl & 0xFF, func & 0xFF]) + body


def allobj(group: int, var: int) -> bytes:
    return bytes([group & 0xFF, var & 0xFF, 0x06])  # all objects


def range8(group: int, var: int, start: int, stop: int) -> bytes:
    return bytes([group & 0xFF, var & 0xFF, 0x00, start & 0xFF, stop & 0xFF])


def range16(group: int, var: int, start: int, stop: int) -> bytes:
    return bytes([
        group & 0xFF, var & 0xFF, 0x01,
        start & 0xFF, (start >> 8) & 0xFF,
        stop & 0xFF, (stop >> 8) & 0xFF
    ])


def count8(group: int, var: int, count: int) -> bytes:
    return bytes([group & 0xFF, var & 0xFF, 0x07, count & 0xFF])


def count16(group: int, var: int, count: int) -> bytes:
    return bytes([group & 0xFF, var & 0xFF, 0x08, count & 0xFF, (count >> 8) & 0xFF])


def pref8(group: int, var: int, objects):
    """
    qualifier 0x17 = 1-byte count, 1-byte index prefix per object
    objects: list[(index, encoded_object_bytes)]
    """
    body = bytearray([group & 0xFF, var & 0xFF, 0x17, len(objects) & 0xFF])
    for idx, obj in objects:
        body.append(idx & 0xFF)
        body += obj
    return bytes(body)


def pref16(group: int, var: int, objects):
    """
    qualifier 0x28 = 2-byte count, 2-byte index prefix per object
    objects: list[(index, encoded_object_bytes)]
    """
    body = bytearray([group & 0xFF, var & 0xFF, 0x28, len(objects) & 0xFF, (len(objects) >> 8) & 0xFF])
    for idx, obj in objects:
        body += bytes([idx & 0xFF, (idx >> 8) & 0xFF])
        body += obj
    return bytes(body)


def crob(raw_code: int = 0x03, count: int = 1, on_ms: int = 100, off_ms: int = 100, status: int = 0) -> bytes:
    """
    Group12Var1 Control Relay Output Block:
      rawCode(1), count(1), onTime(4 LE), offTime(4 LE), status(1)
    """
    return bytes([raw_code & 0xFF, count & 0xFF]) + on_ms.to_bytes(4, "little") + off_ms.to_bytes(4, "little") + bytes([status & 0xFF])


def ao_int16(v: int) -> bytes:
    return int(v).to_bytes(2, "little", signed=True)


def ao_int32(v: int) -> bytes:
    return int(v).to_bytes(4, "little", signed=True)


def ao_f32(v: float) -> bytes:
    return struct.pack("<f", float(v))


def ao_f64(v: float) -> bytes:
    return struct.pack("<d", float(v))


def mutate_bad_header_crc(frame: bytes) -> bytes:
    out = bytearray(frame)
    if len(out) >= 10:
        out[8] ^= 0x01
    return bytes(out)


def mutate_bad_first_data_crc(frame: bytes) -> bytes:
    out = bytearray(frame)
    if len(out) >= 12:
        # first data CRC is always the last 2 bytes for short single-chunk frames
        out[-1] ^= 0x01
    return bytes(out)


def main():
    out_valid = Path("seeds_valid")
    out_boundary = Path("seeds_boundary")
    out_valid.mkdir(parents=True, exist_ok=True)
    out_boundary.mkdir(parents=True, exist_ok=True)

    seeds_valid = {}
    seeds_boundary = {}

    # -------------------------
    # Core link-layer seeds
    # -------------------------
    seeds_valid["01_ll_reset_link.bin"] = dnp3_frame(b"", link_ctrl=0xC0)           # RESET_LINK_STATES
    seeds_valid["02_ll_request_link_status.bin"] = dnp3_frame(b"", link_ctrl=0xC9)  # REQUEST_LINK_STATUS

    # -------------------------
    # High-value READ seeds
    # -------------------------
    seeds_valid["10_read_class0_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(60, 1)))
    seeds_valid["11_read_class1_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(60, 2)))
    seeds_valid["12_read_class2_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(60, 3)))
    seeds_valid["13_read_class3_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(60, 4)))

    seeds_valid["14_read_g1v0_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(1, 0)))
    seeds_valid["15_read_g3v0_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(3, 0)))
    seeds_valid["16_read_g20v0_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(20, 0)))
    seeds_valid["17_read_g21v0_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(21, 0)))
    seeds_valid["18_read_g30v0_all.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(30, 0)))

    seeds_valid["19_read_g1v0_range8_0_9.bin"] = dnp3_frame(app_user(func=0x01, body=range8(1, 0, 0, 9)))
    seeds_valid["20_read_g3v0_range8_0_9.bin"] = dnp3_frame(app_user(func=0x01, body=range8(3, 0, 0, 9)))
    seeds_valid["21_read_g20v0_range16_0_9.bin"] = dnp3_frame(app_user(func=0x01, body=range16(20, 0, 0, 9)))
    seeds_valid["22_read_g21v0_range16_0_9.bin"] = dnp3_frame(app_user(func=0x01, body=range16(21, 0, 0, 9)))
    seeds_valid["23_read_g30v0_range8_0_9.bin"] = dnp3_frame(app_user(func=0x01, body=range8(30, 0, 0, 9)))

    seeds_valid["24_read_multi_header_static.bin"] = dnp3_frame(
        app_user(
            func=0x01,
            body=allobj(1, 0) + allobj(3, 0) + allobj(20, 0) + allobj(21, 0) + allobj(30, 0)
        )
    )

    seeds_valid["25_read_count8_g30_1.bin"] = dnp3_frame(app_user(func=0x01, body=count8(30, 0, 1)))
    seeds_valid["26_read_count16_g30_10.bin"] = dnp3_frame(app_user(func=0x01, body=count16(30, 0, 10)))

    # -------------------------
    # Unsolicited / lifecycle
    # -------------------------
    seeds_valid["30_disable_unsol_class123.bin"] = dnp3_frame(
        app_user(func=0x15, body=allobj(60, 2) + allobj(60, 3) + allobj(60, 4))
    )
    seeds_valid["31_enable_unsol_class123.bin"] = dnp3_frame(
        app_user(func=0x14, body=allobj(60, 2) + allobj(60, 3) + allobj(60, 4))
    )
    seeds_valid["32_cold_restart.bin"] = dnp3_frame(app_user(func=0x0D, body=b""))
    seeds_valid["33_warm_restart.bin"] = dnp3_frame(app_user(func=0x0E, body=b""))
    seeds_valid["34_delay_measure.bin"] = dnp3_frame(app_user(func=0x17, body=b""))

    # -------------------------
    # Command-path seeds
    # SuccessCommandHandler makes these especially worthwhile.
    # -------------------------
    seeds_valid["40_select_crob_idx0.bin"] = dnp3_frame(
        app_user(func=0x03, body=pref8(12, 1, [(0, crob(0x03, 1, 100, 100, 0))])))
    seeds_valid["41_operate_crob_idx0.bin"] = dnp3_frame(
        app_user(func=0x04, body=pref8(12, 1, [(0, crob(0x03, 1, 100, 100, 0))])))
    seeds_valid["42_direct_operate_crob_idx0.bin"] = dnp3_frame(
        app_user(func=0x05, body=pref8(12, 1, [(0, crob(0x03, 1, 100, 100, 0))])))
    seeds_valid["43_direct_operate_noack_crob_idx0.bin"] = dnp3_frame(
        app_user(func=0x06, body=pref8(12, 1, [(0, crob(0x04, 2, 1, 1, 0))])) ,
        link_ctrl=0xC4  # unconfirmed user data
    )

    seeds_valid["44_select_ao_i16_idx0.bin"] = dnp3_frame(
        app_user(func=0x03, body=pref8(41, 2, [(0, ao_int16(7))])))
    seeds_valid["45_operate_ao_i32_idx0.bin"] = dnp3_frame(
        app_user(func=0x04, body=pref8(41, 1, [(0, ao_int32(7))])))
    seeds_valid["46_direct_operate_ao_f32_idx0.bin"] = dnp3_frame(
        app_user(func=0x05, body=pref8(41, 3, [(0, ao_f32(1.5))])))
    seeds_valid["47_direct_operate_noack_ao_f64_idx0.bin"] = dnp3_frame(
        app_user(func=0x06, body=pref16(41, 4, [(0, ao_f64(3.14159))])),
        link_ctrl=0xC4
    )

    # -------------------------
    # Concatenated/stateful seeds
    # -------------------------
    seeds_valid["50_concat_reset_then_class0.bin"] = seeds_valid["01_ll_reset_link.bin"] + seeds_valid["10_read_class0_all.bin"]
    seeds_valid["51_concat_disable_enable_read.bin"] = (
        seeds_valid["30_disable_unsol_class123.bin"] +
        seeds_valid["31_enable_unsol_class123.bin"] +
        seeds_valid["11_read_class1_all.bin"]
    )
    seeds_valid["52_concat_select_operate_crob.bin"] = (
        seeds_valid["40_select_crob_idx0.bin"] +
        seeds_valid["41_operate_crob_idx0.bin"]
    )

    # -------------------------
    # Boundary / parser-hardening seeds
    # These are deliberately near-valid, not pure random trash.
    # -------------------------
    seeds_boundary["60_bad_dest_addr_class0.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(60, 1)), dest=11, src=1)
    seeds_boundary["61_bad_src_addr_class0.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(60, 1)), dest=10, src=2)
    seeds_boundary["62_bad_header_crc_class0.bin"] = mutate_bad_header_crc(seeds_valid["10_read_class0_all.bin"])
    seeds_boundary["63_bad_data_crc_class0.bin"] = mutate_bad_first_data_crc(seeds_valid["10_read_class0_all.bin"])

    tmp = bytearray(seeds_valid["10_read_class0_all.bin"])
    tmp[0] = 0x04  # invalid first start octet
    seeds_boundary["64_bad_start_octet_class0.bin"] = bytes(tmp)

    seeds_boundary["65_invalid_app_func.bin"] = dnp3_frame(app_user(func=0x7F, body=allobj(60, 1)))
    seeds_boundary["66_invalid_qualifier_g30.bin"] = dnp3_frame(app_user(func=0x01, body=bytes([30, 0, 0x5B, 0x00, 0x00])))
    seeds_boundary["67_reserved_group255.bin"] = dnp3_frame(app_user(func=0x01, body=allobj(255, 0)))
    seeds_boundary["68_truncated_after_app_header.bin"] = dnp3_frame(bytes([0xC0, 0xC0, 0x01]))[:-1]
    seeds_boundary["69_count8_ff_g30.bin"] = dnp3_frame(app_user(func=0x01, body=count8(30, 0, 0xFF)))

    for name, data in seeds_valid.items():
        (out_valid / name).write_bytes(data)

    for name, data in seeds_boundary.items():
        (out_boundary / name).write_bytes(data)

    dict_lines = [
        '# opendnp3 outstation AFL dictionary',
        '# Prefer using this together with the generated valid corpus.',
        '',
        'start="\\x05\\x64"',
        '',
        '# link control bytes (master -> outstation)',
        'll_reset="\\xC0"',
        'll_unconfirmed_user_data="\\xC4"',
        'll_request_link_status="\\xC9"',
        'll_test_link="\\xD2"',
        'll_confirmed_user_data="\\xD3"',
        '',
        '# transport/app control',
        'tp_fir_fin_seq0="\\xC0"',
        'tp_fir_fin_seq1="\\xC1"',
        'tp_fir_fin_seq2="\\xC2"',
        'tp_fir_fin_seq3="\\xC3"',
        'tp_fir_fin_seq11="\\xCB"',
        '',
        'app_ctrl_seq0="\\xC0"',
        'app_ctrl_seq1="\\xC1"',
        'app_ctrl_seq2="\\xC2"',
        'app_ctrl_seq3="\\xC3"',
        'app_ctrl_uns_seq0="\\xD0"',
        '',
        '# application function codes',
        'fc_confirm="\\x00"',
        'fc_read="\\x01"',
        'fc_write="\\x02"',
        'fc_select="\\x03"',
        'fc_operate="\\x04"',
        'fc_direct_operate="\\x05"',
        'fc_direct_operate_noack="\\x06"',
        'fc_cold_restart="\\x0D"',
        'fc_warm_restart="\\x0E"',
        'fc_enable_unsol="\\x14"',
        'fc_disable_unsol="\\x15"',
        'fc_assign_class="\\x16"',
        'fc_delay_measure="\\x17"',
        'fc_record_current_time="\\x18"',
        'fc_response="\\x81"',
        'fc_unsol_response="\\x82"',
        '',
        '# high-value object headers',
        'g60v1_all="\\x3C\\x01\\x06"',
        'g60v2_all="\\x3C\\x02\\x06"',
        'g60v3_all="\\x3C\\x03\\x06"',
        'g60v4_all="\\x3C\\x04\\x06"',
        'g01v0_all="\\x01\\x00\\x06"',
        'g03v0_all="\\x03\\x00\\x06"',
        'g10v0_all="\\x0A\\x00\\x06"',
        'g20v0_all="\\x14\\x00\\x06"',
        'g21v0_all="\\x15\\x00\\x06"',
        'g30v0_all="\\x1E\\x00\\x06"',
        'g40v0_all="\\x28\\x00\\x06"',
        '',
        '# range / count qualifiers',
        'q_range8_0_9="\\x00\\x00\\x09"',
        'q_range16_0_9="\\x01\\x00\\x00\\x09\\x00"',
        'q_count8_1="\\x07\\x01"',
        'q_count8_10="\\x07\\x0A"',
        'q_count16_10="\\x08\\x0A\\x00"',
        'q_pref8_idx0_count1="\\x17\\x01\\x00"',
        'q_pref16_idx0_count1="\\x28\\x01\\x00\\x00\\x00"',
        '',
        '# addresses from the example config',
        'addr_outstation_10="\\x0A\\x00"',
        'addr_master_1="\\x01\\x00"',
        'addr_broadcast="\\xFF\\xFF"',
        'addr_reserved_floor="\\xF0\\xFF"',
        '',
        '# CROB payloads (Group12Var1 objects without qualifier/index)',
        'crob_latch_on_default="\\x03\\x01\\x64\\x00\\x00\\x00\\x64\\x00\\x00\\x00\\x00"',
        'crob_latch_off_short="\\x04\\x02\\x01\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00"',
        'crob_pulse_on="\\x01\\x01\\x32\\x00\\x00\\x00\\x32\\x00\\x00\\x00\\x00"',
        'crob_pulse_off="\\x02\\x01\\x32\\x00\\x00\\x00\\x32\\x00\\x00\\x00\\x00"',
        '',
        '# Analog output object payloads (without qualifier/index)',
        'ao_i16_0="\\x00\\x00"',
        'ao_i16_1="\\x01\\x00"',
        'ao_i16_neg1="\\xFF\\xFF"',
        'ao_i16_max="\\xFF\\x7F"',
        'ao_i16_min="\\x00\\x80"',
        '',
        'ao_i32_0="\\x00\\x00\\x00\\x00"',
        'ao_i32_1="\\x01\\x00\\x00\\x00"',
        'ao_i32_neg1="\\xFF\\xFF\\xFF\\xFF"',
        'ao_i32_max="\\xFF\\xFF\\xFF\\x7F"',
        'ao_i32_min="\\x00\\x00\\x00\\x80"',
        '',
        'ao_f32_1_0="\\x00\\x00\\x80\\x3F"',
        'ao_f32_1_5="\\x00\\x00\\xC0\\x3F"',
        'ao_f32_neg1_0="\\x00\\x00\\x80\\xBF"',
        'ao_f32_nan="\\x00\\x00\\xC0\\x7F"',
        'ao_f32_inf="\\x00\\x00\\x80\\x7F"',
        '',
        'ao_f64_pi="\\x6E\\x86\\x1B\\xF0\\xF9\\x21\\x09\\x40"',
        'ao_f64_neg1="\\x00\\x00\\x00\\x00\\x00\\x00\\xF0\\xBF"',
        'ao_f64_nan="\\x00\\x00\\x00\\x00\\x00\\x00\\xF8\\x7F"',
        'ao_f64_inf="\\x00\\x00\\x00\\x00\\x00\\x00\\xF0\\x7F"',
    ]

    Path("opendnp3_outstation.dict").write_text("\n".join(dict_lines) + "\n", encoding="utf-8")

    print("Generated:")
    print("  seeds_valid/")
    print("  seeds_boundary/")
    print("  opendnp3_outstation.dict")
    print()
    print("Suggested AFL++ usage:")
    print("  afl-fuzz -i seeds_valid -x opendnp3_outstation.dict -o outputs -M out_m0 -- ./outstation_fuzz 20000")
    print("  afl-fuzz -i seeds_valid -x opendnp3_outstation.dict -o outputs -S out_s1 -- ./outstation_fuzz 20001")
    print("  afl-fuzz -i seeds_valid -x opendnp3_outstation.dict -o outputs -S out_s2 -- ./outstation_fuzz 20002")
    print("  afl-fuzz -i seeds_valid -x opendnp3_outstation.dict -o outputs -S out_s3 -- ./outstation_fuzz 20003")


if __name__ == "__main__":
    main()

