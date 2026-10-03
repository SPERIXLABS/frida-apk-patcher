#!/usr/bin/python3

###
# Copyright (c) 2016 Nishant Das Patnaik.
# Copyright (c) 2024-2026 Jay Lux Ferro
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

"""APK Builder - makes an APK "inspectable" on non-rooted Android devices.

Two independent stages:

1. Gadget injection (optional, --manifest-only skips it): embeds the Frida
   gadget and loads it from the launchable activity. Needs apktool, because
   dex-level code changes still mean smali.

2. Manifest/resource patching (always runs, zip surgery): adds
   android:debuggable, android:usesCleartextTraffic, a debug
   networkSecurityConfig and extractNativeLibs to ANY apk - WITHOUT
   apktool decode/rebuild. Ported from APKProxyHelper.py (same author,
   Apache-2.0), where it replaced an apktool round-trip that died on
   apps whose resources apktool 2.10 fails to parse (HDO Box 4.4.6:
   res/qz.xml -> "Could not decode file, replacing by FALSE value" ->
   aapt2 compile error on rebuild). The manifest is edited as binary
   AXML and the NSC resource is appended to the original arsc in place;
   every other zip entry is copied byte-for-byte.

   If the gadget stage fails, the build automatically falls back to
   manifest-only so you still get a usable, signed, patched apk.

Two Android framework rules this port encodes (learned the hard way, see
the project memory note "axml-attr-order-and-compiled-xml"):
  - manifest attributes MUST be re-sorted ascending by resource id after
    editing: AttributeResolution.cpp merge-walks both arrays and silently
    skips out-of-order attrs (aapt2 dump xmltree still shows them!);
  - res/xml payloads MUST be COMPILED binary XML - a text NSC installs
    fine and then kills the app at bind time.
"""

import argparse
import codecs
import glob
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import traceback
import zipfile
import xml.etree.ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# android framework attr resource ids. debuggable/usesCleartextTraffic/
# networkSecurityConfig verified against aapt2 output in APKProxyHelper;
# extractNativeLibs and uses-permission/name re-verified the same way
# (aapt2 link a manifest carrying them, aapt2 dump xmltree) - do not
# "fix" any of these from memory, they look deceptively regular.
ATTR_ID_DEBUGGABLE = 0x0101000F
ATTR_ID_USES_CLEARTEXT = 0x010104EC
ATTR_ID_NETWORK_SECURITY_CONFIG = 0x01010527
ATTR_ID_EXTRACT_NATIVE_LIBS = 0x010104EA
ATTR_ID_NAME = 0x01010003

# Res_value.dataType codes
VAL_TYPE_REFERENCE = 0x01
VAL_TYPE_STRING = 0x03
VAL_TYPE_BOOLEAN = 0x12

BOOL_TRUE = 0xFFFFFFFF  # convention: any non-zero is true, aapt writes -1

NO_INDEX = 0xFFFFFFFF

NSC_FILE_NAME = "network_security_config.xml"
NSC_RES_NAME = "network_security_config"

# debug NSC: user CAs trusted (mitm proxy CA) + cleartext explicitly allowed.
# cleartextTrafficPermitted must be spelled out: the default is NOT
# permitted-per-what-you'd-hope, and relying on defaults is what bit the
# manual HDO Box bypass. The repo file is preferred when present so the
# operator can tweak it; this constant is the fallback.
DEFAULT_NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""


def find_build_tools():
    """Locate zipalign/apksigner under $ANDROID_HOME or the common macOS path."""
    home = os.environ.get("ANDROID_HOME") or os.path.expanduser("~/androidSdk")
    bt = os.path.join(home, "build-tools")
    versions = sorted(os.listdir(bt), reverse=True) if os.path.isdir(bt) else []
    # prefer 34.0.0 (matches the audit bench toolchain), else newest
    if "34.0.0" in versions:
        versions = ["34.0.0"] + [v for v in versions if v != "34.0.0"]
    for v in versions:
        if os.path.isfile(os.path.join(bt, v, "zipalign")) and os.path.isfile(
            os.path.join(bt, v, "apksigner")
        ):
            return os.path.join(bt, v)
    raise FileNotFoundError("zipalign/apksigner not found under %s - set ANDROID_HOME" % bt)


# ---------------------------------------------------------------------------
# Binary string pool (ResStringPool) - used by both AXML and resources.arsc.
# Ported verbatim from APKProxyHelper.py (Jay Lux Ferro, Apache-2.0).
# Handles UTF-8 and UTF-16 pools. Style spans (styled strings) are preserved
# verbatim: we only ever APPEND strings, so original indices (which spans
# refer to) stay valid.
# ---------------------------------------------------------------------------


class StringPool:
    def __init__(self):
        self.utf8 = True
        self.strings = []
        self._style_offsets = []  # u32 offsets into the spans block, verbatim
        self._styles = b""  # raw span block incl. sentinel, kept verbatim
        self._style_count = 0

    @staticmethod
    def parse(data, off):
        pool = StringPool()
        chunk_type, header_size = struct.unpack_from("<HH", data, off)
        if chunk_type != 0x0001:
            raise ValueError("expected string pool chunk, got 0x%04x" % chunk_type)
        (chunk_size,) = struct.unpack_from("<I", data, off + 4)
        pool.size = chunk_size
        (str_count, style_count, flags, strings_start, styles_start) = struct.unpack_from(
            "<IIIII", data, off + 8
        )
        pool.utf8 = bool(flags & 0x100)
        pool._style_count = style_count
        offsets = struct.unpack_from("<%dI" % str_count, data, off + 28)
        # LAYOUT GOTCHA (found on PCAPdroid, whose arsc global pool carries
        # styled strings): the STYLE OFFSETS table is NOT at stylesStart -
        # androidfw hardcodes it right after the string offsets, at
        # headerSize + 4*stringCount; stylesStart points at the SPAN
        # structures only. Pools without styles make both readings coincide,
        # which is why the bug stayed hidden until a styled pool showed up.
        if style_count > 0:
            pool._style_offsets = list(
                struct.unpack_from(
                    "<%dI" % style_count, data, off + 28 + 4 * str_count
                )
            )
        base = off + strings_start
        for o in offsets:
            p = base + o
            if pool.utf8:
                _, p = StringPool._decode_len8(data, p)
                u8len, p = StringPool._decode_len8(data, p)
                pool.strings.append(data[p : p + u8len].decode("utf-8", "replace"))
            else:
                u16len, p = StringPool._decode_len16(data, p)
                pool.strings.append(
                    data[p : p + 2 * u16len].decode("utf-16-le", "replace")
                )
        if style_count > 0:
            pool._styles = bytes(data[off + styles_start : off + chunk_size])
        return pool

    @staticmethod
    def _decode_len8(data, p):
        l = data[p]
        p += 1
        if l & 0x80:
            l = ((l & 0x7F) << 8) | data[p]
            p += 1
        return l, p

    @staticmethod
    def _decode_len16(data, p):
        l = struct.unpack_from("<H", data, p)[0]
        p += 2
        if l & 0x8000:
            l = ((l & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
            p += 2
        return l, p

    @staticmethod
    def _encode_len8(v):
        if v < 0x80:
            return bytes([v])
        return bytes([0x80 | (v >> 8), v & 0xFF])

    @staticmethod
    def _encode_len16(v):
        if v < 0x8000:
            return struct.pack("<H", v)
        return struct.pack("<HH", 0x8000 | (v >> 16), v & 0xFFFF)

    def index_of(self, s):
        try:
            return self.strings.index(s)
        except ValueError:
            return -1

    def append(self, s):
        """Append string, returning its index (dedup: reuse if present)."""
        idx = self.index_of(s)
        if idx >= 0:
            return idx
        self.strings.append(s)
        return len(self.strings) - 1

    def _encode_string(self, s):
        # aapt measures length in UTF-16 code units, not code points
        u16len = len(s.encode("utf-16-le")) // 2
        if self.utf8:
            raw = s.encode("utf-8")
            return self._encode_len8(u16len) + self._encode_len8(len(raw)) + raw + b"\x00"
        return self._encode_len16(u16len) + s.encode("utf-16-le") + b"\x00\x00"

    def serialize(self):
        # The SORTED flag (0x1) is dropped on rewrite: appended strings would
        # break sort order, and unsorted pools are always legal (lookups fall
        # back to a linear scan).
        flags = 0x100 if self.utf8 else 0x0
        enc = [self._encode_string(s) for s in self.strings]
        count = len(self.strings)
        # [header][string offsets][style offsets][strings][spans] - see the
        # layout note in parse(); the style offsets table must be re-emitted
        # in its hardcoded slot even though stylesStart points elsewhere.
        strings_start = 28 + 4 * count + 4 * len(self._style_offsets)
        strings_start += (-strings_start) % 4
        if self._style_count > 0:
            styles_start = strings_start + sum(len(e) for e in enc)
            styles_start += (-styles_start) % 4  # spans need 4-byte alignment
            chunk_size = styles_start + len(self._styles)
        else:
            styles_start = 0
            chunk_size = strings_start + sum(len(e) for e in enc)
        chunk_size += (-chunk_size) % 4
        out = bytearray(
            struct.pack(
                "<HHIIIIII",
                0x0001,
                28,
                chunk_size,
                count,
                self._style_count,
                flags,
                strings_start,
                styles_start,
            )
        )
        cur = 0
        for e in enc:
            out += struct.pack("<I", cur)
            cur += len(e)
        for so in self._style_offsets:
            out += struct.pack("<I", so)
        out += b"\x00" * (strings_start - len(out))
        for e in enc:
            out += e
        if self._style_count > 0:
            out += b"\x00" * (styles_start - len(out))
            out += self._styles
        out += b"\x00" * (chunk_size - len(out))
        return bytes(out)


class AxmlNode:
    START_NS = 0x0100
    END_NS = 0x0101
    START_ELEMENT = 0x0102
    END_ELEMENT = 0x0103
    CDATA = 0x0104


class Attribute:
    def __init__(self, ns, name, raw_value, data_type, data):
        self.ns = ns
        self.name = name  # string pool index
        self.raw_value = raw_value  # string pool index or NO_INDEX
        self.data_type = data_type
        self.data = data


class AxmlDocument:
    def __init__(self, data):
        self.pool = None
        self.res_ids = []  # resource-map entries indexed by string index
        self.nodes = []
        self._parse(data)

    def _parse(self, data):
        xml_type, xml_hdr, xml_size = struct.unpack_from("<HHI", data, 0)
        if xml_type != 0x0003:
            raise ValueError("not an AXML document (type=0x%04x)" % xml_type)
        off = xml_hdr
        while off < xml_size:
            chunk_type, chunk_hdr = struct.unpack_from("<HH", data, off)
            (chunk_size,) = struct.unpack_from("<I", data, off + 4)
            line = struct.unpack_from("<I", data, off + 8)[0]
            comment = struct.unpack_from("<I", data, off + 12)[0]
            if chunk_type == 0x0001:
                self.pool = StringPool.parse(data, off)
            elif chunk_type == 0x0180:
                n = (chunk_size - chunk_hdr) // 4
                self.res_ids = list(struct.unpack_from("<%dI" % n, data, off + chunk_hdr))
            elif chunk_type in (AxmlNode.START_NS, AxmlNode.END_NS):
                prefix, uri = struct.unpack_from("<II", data, off + 16)
                self.nodes.append(
                    dict(kind=chunk_type, line=line, comment=comment, prefix=prefix, uri=uri)
                )
            elif chunk_type == AxmlNode.START_ELEMENT:
                ns, name = struct.unpack_from("<II", data, off + 16)
                attr_start, attr_size, attr_count, id_idx, class_idx, style_idx = struct.unpack_from(
                    "<HHHHHH", data, off + 24
                )
                attrs = []
                abase = off + 16 + attr_start
                for i in range(attr_count):
                    a = abase + i * attr_size
                    ans, aname, raw = struct.unpack_from("<III", data, a)
                    vsize, vres0, vtype, vdata = struct.unpack_from("<HBBI", data, a + 12)
                    attrs.append(Attribute(ans, aname, raw, vtype, vdata))
                self.nodes.append(
                    dict(
                        kind=chunk_type,
                        line=line,
                        comment=comment,
                        ns=ns,
                        name=name,
                        attr_start=attr_start,
                        attr_size=attr_size,
                        id_idx=id_idx,
                        class_idx=class_idx,
                        style_idx=style_idx,
                        attrs=attrs,
                    )
                )
            elif chunk_type == AxmlNode.END_ELEMENT:
                ns, name = struct.unpack_from("<II", data, off + 16)
                self.nodes.append(dict(kind=chunk_type, line=line, comment=comment, ns=ns, name=name))
            elif chunk_type == AxmlNode.CDATA:
                (cdata,) = struct.unpack_from("<I", data, off + 16)
                self.nodes.append(dict(kind=chunk_type, line=line, comment=comment, data=cdata))
            else:
                # unknown chunk kind: keep bytes verbatim
                self.nodes.append(dict(kind=chunk_type, raw=bytes(data[off : off + chunk_size])))
            off += chunk_size

    # -- helpers -------------------------------------------------------------

    def elements(self, name):
        for n in self.nodes:
            if n["kind"] == AxmlNode.START_ELEMENT and self.pool.strings[n["name"]] == name:
                yield n

    def android_ns_index(self):
        idx = self.pool.index_of(ANDROID_NS)
        if idx >= 0:
            return idx
        return self.pool.append(ANDROID_NS)

    def str_index(self, s):
        return self.pool.append(s)

    def find_android_attr(self, node, attr_name):
        for a in node["attrs"]:
            if a.ns != NO_INDEX and self.pool.strings[a.name] == attr_name:
                return a
        return None

    ATTR_IDS = {
        "debuggable": ATTR_ID_DEBUGGABLE,
        "usesCleartextTraffic": ATTR_ID_USES_CLEARTEXT,
        "networkSecurityConfig": ATTR_ID_NETWORK_SECURITY_CONFIG,
        "extractNativeLibs": ATTR_ID_EXTRACT_NATIVE_LIBS,
    }

    def set_or_add_attr(self, node, attr_name, data_type, data, raw):
        ns = self.android_ns_index()
        name_idx = self.str_index(attr_name)
        raw_idx = self.str_index(raw) if raw is not None else NO_INDEX
        a = self.find_android_attr(node, attr_name)
        if a is None:
            node["attrs"].append(Attribute(ns, name_idx, raw_idx, data_type, data))
        else:
            a.ns = ns
            a.data_type = data_type
            a.data = data
            a.raw_value = raw_idx
        # PackageParser matches attributes by RESOURCE ID via the resource-map
        # chunk, so the map must carry the framework attr id for every attr
        # name we touch. Extend it to cover the whole string pool (a map
        # longer than the original is always safe; shorter would not be).
        while len(self.res_ids) < len(self.pool.strings):
            self.res_ids.append(0)
        self.res_ids[name_idx] = self.ATTR_IDS[attr_name]
        # AssetManager2::RetrieveAttributes (AttributeResolution.cpp) - the
        # code behind every obtainAttributes() on a manifest - does an
        # ascending MERGE-WALK over the requested styleable array and the
        # element's attributes, assuming both are sorted by resource id
        # (which aapt2 guarantees for files it emits). An out-of-order
        # attribute is skipped SILENTLY: aapt2 dump xmltree still resolves
        # it, but debuggable/usesCleartextTraffic simply do not apply at
        # runtime. Re-sort into canonical order (attrs without a resource
        # id - e.g. tools:/package - go last, relative order preserved).
        node["attrs"].sort(key=self._attr_sort_key)

    def _attr_sort_key(self, a):
        resid = self.res_ids[a.name] if a.name < len(self.res_ids) else 0
        return (1 if resid == 0 else 0, resid)

    # -- serialization -------------------------------------------------------

    def serialize(self):
        out = bytearray()
        out += struct.pack("<HHI", 0x0003, 8, 0)  # size patched at the end
        out += self.pool.serialize()
        if self.res_ids:  # synthetic docs (compiled NSC) carry no resource map
            out += self._serialize_res_map()
        for n in self.nodes:
            out += self._serialize_node(n)
        struct.pack_into("<I", out, 4, len(out))
        return bytes(out)

    def _serialize_res_map(self):
        data = b"".join(struct.pack("<I", v) for v in self.res_ids)
        return struct.pack("<HHI", 0x0180, 8, 8 + len(data)) + data

    def _node_header(self, n, body_len):
        # ResXMLTree_node: {type, headerSize=16, size, lineNumber, comment}
        size = 16 + body_len
        return struct.pack(
            "<HHIII", n["kind"], 16, size, n.get("line", 0), n.get("comment", NO_INDEX)
        )

    def _serialize_node(self, n):
        k = n["kind"]
        if "raw" in n:
            return n["raw"]
        if k in (AxmlNode.START_NS, AxmlNode.END_NS):
            return self._node_header(n, 8) + struct.pack("<II", n["prefix"], n["uri"])
        if k == AxmlNode.CDATA:
            return self._node_header(n, 4) + struct.pack("<I", n["data"])
        if k == AxmlNode.END_ELEMENT:
            return self._node_header(n, 8) + struct.pack("<II", n["ns"], n["name"])
        if k == AxmlNode.START_ELEMENT:
            # attrExt: ns, name, attributeStart(0x14), attributeSize(0x14),
            # attributeCount, idIndex, classIndex, styleIndex
            attr_ext = struct.pack(
                "<IIHHHHHH",
                n["ns"],
                n["name"],
                0x14,
                0x14,
                len(n["attrs"]),
                n["id_idx"],
                n["class_idx"],
                n["style_idx"],
            )
            attrs = b"".join(self._serialize_attr(a) for a in n["attrs"])
            return self._node_header(n, len(attr_ext) + len(attrs)) + attr_ext + attrs
        raise ValueError("unserializable node kind 0x%04x" % k)

    @staticmethod
    def _serialize_attr(a):
        # ResXMLTree_attribute + typed value = 20 bytes:
        # ns(I) name(I) rawValue(I) | typedValue: size(H) res0(B) dataType(B) data(I)
        return struct.pack("<IIIHBBI", a.ns, a.name, a.raw_value, 8, 0, a.data_type, a.data)


def compile_xml_to_axml(text):
    """Compile a simple text XML resource to binary AXML.

    The framework reads res/xml resources through ResXMLTree, which only
    accepts COMPILED binary XML: the text payload the old apk_builder
    embedded via apktool decode/rebuild decodes fine with `aapt2 dump` but
    was one apktool round-trip away from not existing at all - and dropping
    raw text into res/xml directly kills the app at bind time ("Failed to
    parse XML configuration from ..."). aapt2 does this compilation in a
    normal build; reimplemented here so the tool stays self-contained.
    Scope is exactly the NSC schema: nested elements with namespace-free
    string-valued attributes, no text content, no resource references -
    anything else raises rather than emitting broken AXML.
    """
    root = ET.fromstring(text)
    doc = AxmlDocument.__new__(AxmlDocument)
    doc.pool = StringPool()  # utf-8 pool, like aapt2 writes for xml resources
    doc.res_ids = []  # no resource map: the NSC parser reads attrs by name
    doc.nodes = []

    def sid(s):
        i = doc.pool.index_of(s)
        return i if i >= 0 else doc.pool.append(s)

    def walk(elem):
        name_idx = sid(elem.tag)
        attrs = []
        for k, v in elem.attrib.items():
            ki, vi = sid(k), sid(v)
            # string attr: rawValue and typed value both point into the pool
            attrs.append(Attribute(NO_INDEX, ki, vi, VAL_TYPE_STRING, vi))
        doc.nodes.append(
            dict(
                kind=AxmlNode.START_ELEMENT,
                line=1,
                comment=NO_INDEX,
                ns=NO_INDEX,
                name=name_idx,
                id_idx=0,
                class_idx=0,
                style_idx=0,
                attrs=attrs,
            )
        )
        if elem.text and elem.text.strip():
            raise ValueError("text content not supported in %s" % elem.tag)
        for child in elem:
            walk(child)
            if child.tail and child.tail.strip():
                raise ValueError("text content not supported in %s" % child.tag)
        doc.nodes.append(
            dict(
                kind=AxmlNode.END_ELEMENT,
                line=1,
                comment=NO_INDEX,
                ns=NO_INDEX,
                name=name_idx,
            )
        )

    walk(root)
    return doc.serialize()


# ---------------------------------------------------------------------------
# resources.arsc editing: append one file-backed entry of type "xml".
# Ported verbatim from APKProxyHelper.py. The original arsc is never
# decoded/regenerated - only grown at chunk boundaries - so
# obfuscated/unusual resources survive untouched.
# ---------------------------------------------------------------------------


class ArscPackage:
    def __init__(self, data, off):
        self.off = off
        (self.chunk_type, self.header_size, self.size, self.id) = struct.unpack_from(
            "<HHII", data, off
        )
        self.raw_name = bytes(data[off + 12 : off + 268])  # 128 UTF-16 units, verbatim
        (
            self.type_strings_off,
            self.last_public_type,
            self.key_strings_off,
            self.last_public_key,
            self.type_id_offset,
        ) = struct.unpack_from("<IIIII", data, off + 268)
        self.type_pool = StringPool.parse(data, off + self.type_strings_off)
        self.key_pool = StringPool.parse(data, off + self.key_strings_off)
        # type spec/type chunks follow the key strings pool (the two string
        # pools sit between the fixed header and them); keep them in original
        # order. Parsed dicts carry enough state to rebuild a modified chunk,
        # raw bytes are copied verbatim otherwise.
        self.chunks = []
        c = off + self.key_strings_off + self.key_pool.size
        end = off + self.size
        while c < end:
            ctype, chdr = struct.unpack_from("<HH", data, c)
            (csize,) = struct.unpack_from("<I", data, c + 4)
            entry = dict(kind=ctype, raw=bytes(data[c : c + csize]))
            if ctype in (0x0201, 0x0204):
                flags = struct.unpack_from("<H", data, c + 10)[0]
                entry.update(
                    dict(
                        type_id=data[c + 8],
                        flags=flags,
                        entry_count=struct.unpack_from("<I", data, c + 12)[0],
                        entries_start=struct.unpack_from("<I", data, c + 16)[0],
                        config_size=struct.unpack_from("<I", data, c + 20)[0],
                        header_size=chdr,
                        is_sparse=(ctype == 0x0204 or bool(flags & 0x01)),
                        is_off16=bool(flags & 0x02),
                    )
                )
            elif ctype == 0x0202:
                entry.update(dict(type_id=data[c + 8]))
            self.chunks.append(entry)
            c += csize

    def type_index(self, type_name):
        try:
            return self.type_pool.strings.index(type_name) + 1
        except ValueError:
            return -1

    def type_chunks(self, type_id):
        return [
            c
            for c in self.chunks
            if c.get("type_id") == type_id and c["kind"] in (0x0201, 0x0204)
        ]

    def type_spec(self, type_id):
        for c in self.chunks:
            if c["kind"] == 0x0202 and c.get("type_id") == type_id:
                return c
        return None

    @staticmethod
    def is_default_config(chunk):
        # default config = every qualifier byte zero. The first 4 bytes of the
        # region are ResTable_config.size itself (always non-zero), so compare
        # only the qualifier payload after it.
        region = chunk["raw"][20 : 20 + chunk["config_size"]]
        return region[4:] == b"\x00" * (len(region) - 4)

    def _iter_entries(self, chunk):
        """Yield (entry_index, byte_offset_into_entries_data) for present entries."""
        raw = chunk["raw"]
        hdr = chunk["header_size"]
        n = chunk["entry_count"]
        if n <= 0 or len(raw) <= hdr:
            return
        if chunk["is_sparse"]:
            count = (len(raw) - hdr) // 4
            vals = struct.unpack_from("<%dH" % (2 * count), raw, hdr)
            for i in range(count):
                yield vals[2 * i], vals[2 * i + 1] * 4  # sparse offsets are /4
        elif chunk["is_off16"]:
            offs = struct.unpack_from("<%dH" % (2 * n), raw, hdr)
            for i in range(n):
                off = offs[2 * i] | (offs[2 * i + 1] << 16)
                if off != NO_INDEX:
                    yield i, off * 4
        else:
            offs = struct.unpack_from("<%dI" % n, raw, hdr)
            for i in range(n):
                if offs[i] != NO_INDEX:
                    yield i, offs[i]

    @staticmethod
    def _entry_total_len(raw, p):
        """Byte length of the entry at raw[p] (simple or complex/bag)."""
        esize, eflags = struct.unpack_from("<HH", raw, p)
        if eflags & 0x01:  # COMPLEX: maps follow (20 bytes each)
            count = struct.unpack_from("<I", raw, p + 12)[0]
            return esize + count * 20
        return esize + 8  # + Res_value

    def _entry_value(self, chunk, entry_index):
        """(dataType, data) of a simple entry, or None for bags."""
        raw = chunk["raw"]
        es = chunk["entries_start"]
        for i, off in self._iter_entries(chunk):
            if i == entry_index:
                p = es + off
                eflags = struct.unpack_from("<H", raw, p + 2)[0]
                if eflags & 0x01:
                    return None
                esize = struct.unpack_from("<H", raw, p)[0]
                vsize, vres0, vtype, vdata = struct.unpack_from("<HBBI", raw, p + esize)
                return (vtype, vdata)
        return None

    def entry_file_paths(self, type_id, global_pool):
        """All file-backed entries of a type: {resource_id: file_path}."""
        out = {}
        for chunk in self.type_chunks(type_id):
            for i, _ in self._iter_entries(chunk):
                value = self._entry_value(chunk, i)
                if value and value[0] == VAL_TYPE_STRING:
                    rid = (self.id << 24) | (type_id << 16) | i
                    out[rid] = global_pool.strings[value[1]]
        return out

    def append_file_entry(self, type_id, key_name, file_path, global_pool):
        """Add one file-backed resource to this package; return the resource id.

        The entry goes into the type's DEFAULT-config chunk (created if
        absent). The new entry index is one beyond the highest index used by
        ANY config chunk of the type, so an exact-id lookup can never resolve
        to another config chunk that also happens to contain that index.
        """
        global_idx = global_pool.append(file_path)
        key_idx = self.key_pool.append(key_name)

        chunks = self.type_chunks(type_id)
        entry_idx = max([c["entry_count"] for c in chunks] + [0])
        host = None
        for c in chunks:
            if self.is_default_config(c):
                host = c
                break
        if host is None:
            host = dict(
                kind=0x0201,
                type_id=type_id,
                flags=0,
                entry_count=0,
                entries_start=0,
                config_size=64,
                header_size=84,
                is_sparse=False,
                is_off16=False,
                raw=b"",  # empty config region -> written as default config
            )
            self.chunks.append(host)
            if self.type_spec(type_id) is None:
                # TYPE_SPEC: {hdr(8), id, res0, flags, entryCount} + flags array
                n = entry_idx + 1
                self.chunks.append(
                    dict(
                        kind=0x0202,
                        type_id=type_id,
                        raw=struct.pack("<HHIBBHI", 0x0202, 16, 16 + 4 * n, type_id, 0, 0, n)
                        + b"\x00" * (4 * n),
                    )
                )

        entry = struct.pack("<HHI", 8, 0, key_idx) + struct.pack(
            "<HBBI", 8, 0, VAL_TYPE_STRING, global_idx
        )
        new_raw, new_count = self._rebuild_type_chunk(host, entry_idx, entry)
        host["raw"] = new_raw
        host["entry_count"] = new_count

        spec = self.type_spec(type_id)
        if spec is not None and len(spec["raw"]) >= 16:
            n = struct.unpack_from("<I", spec["raw"], 12)[0]
            if n < host["entry_count"]:
                # grow the entry-flag array to match the new entry count;
                # rebuild the whole chunk so the size field stays truthful
                # (a stale size makes aapt2/framework walk chunks misaligned)
                spec["raw"] = (
                    struct.pack(
                        "<HHIBBHI",
                        0x0202,
                        16,
                        16 + 4 * host["entry_count"],
                        type_id,
                        0,
                        0,
                        host["entry_count"],
                    )
                    + spec["raw"][16:]
                    + b"\x00" * (4 * (host["entry_count"] - n))
                )

        self.last_public_type = max(self.last_public_type, type_id)
        self.last_public_key = max(self.last_public_key, key_idx)
        return (self.id << 24) | (type_id << 16) | entry_idx

    def _rebuild_type_chunk(self, chunk, entry_idx, entry_bytes):
        """Rebuild a type chunk with one more entry.

        Sparse (0x0204) and OFFSET16 chunks are converted to the plain uint32
        offset layout - always valid and the simplest shape to extend. Existing
        entries are copied verbatim; gaps stay as NO_INDEX holes (dense chunks
        with holes are exactly what aapt emits for sparse key spaces).
        """
        raw = chunk["raw"]
        n = chunk["entry_count"]
        config = raw[20 : 20 + chunk["config_size"]]
        hdr_size = 20 + len(config)

        entries = {}
        for i, off in self._iter_entries(chunk):
            p = chunk["entries_start"] + off
            entries[i] = raw[p : p + self._entry_total_len(raw, p)]

        new_count = max(n, entry_idx + 1)
        offsets = []
        data = bytearray()
        for i in range(new_count):
            if i in entries:
                offsets.append(len(data))
                data += entries[i]
            elif i == entry_idx:
                offsets.append(len(data))
                data += entry_bytes
            else:
                offsets.append(NO_INDEX)
        entries_start = hdr_size + 4 * new_count
        entries_start += (-entries_start) % 4
        chunk_size = entries_start + len(data)
        chunk_size += (-chunk_size) % 4
        out = bytearray(
            struct.pack(
                "<HHIBBHII",
                0x0201,
                hdr_size,
                chunk_size,
                chunk["type_id"],
                0,
                0,  # flags: not sparse, not offset16
                new_count,
                entries_start,
            )
        )
        out += config
        out += b"".join(struct.pack("<I", o) for o in offsets)
        out += b"\x00" * (entries_start - len(out))
        out += data
        out += b"\x00" * (chunk_size - len(out))
        return bytes(out), new_count

    def serialize(self):
        tp = self.type_pool.serialize()
        kp = self.key_pool.serialize()
        body = tp + kp + b"".join(c["raw"] for c in self.chunks)
        header = struct.pack("<HHII", 0x0200, self.header_size, self.header_size + len(body), self.id)
        header += self.raw_name
        header += struct.pack(
            "<IIIII",
            self.header_size,  # typeStrings starts right after the fixed header
            self.last_public_type,
            self.header_size + len(tp),  # keyStrings after the type pool
            self.last_public_key,
            self.type_id_offset,
        )
        return header + body


class ArscTable:
    def __init__(self, data):
        self.data = bytes(data)
        (self.chunk_type, self.header_size, self.size, self.package_count) = struct.unpack_from(
            "<HHII", self.data, 0
        )
        if self.chunk_type != 0x0002:
            raise ValueError("not a resources.arsc table (type=0x%04x)" % self.chunk_type)
        self.global_pool = StringPool.parse(self.data, self.header_size)
        self.packages = []
        off = self.header_size + struct.unpack_from("<I", self.data, self.header_size + 4)[0]
        for _ in range(self.package_count):
            pkg = ArscPackage(self.data, off)
            self.packages.append(pkg)
            off += pkg.size

    def app_package(self):
        # the manifest resolves refs against the app's own package (0x7f);
        # fall back to the first package for shared-library style tables
        for p in self.packages:
            if p.id == 0x7F:
                return p
        return self.packages[0] if self.packages else None

    def serialize(self):
        body = self.global_pool.serialize() + b"".join(p.serialize() for p in self.packages)
        header = struct.pack(
            "<HHII", 0x0002, self.header_size, self.header_size + len(body), self.package_count
        )
        return header + body


# ---------------------------------------------------------------------------
# apk_builder's own stage orchestration (frida-gadget injection + zip surgery)
# ---------------------------------------------------------------------------

SMALI_DIRECT_METHODS = """\n.method static constructor <clinit>()V
    .locals 1

    .prologue
    const-string v0, "frida-gadget"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method

"""

SMALI_PROLOGUE = """\n    const-string v0, "frida-gadget"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

"""

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_FILE_PATH = os.path.join(SCRIPT_DIR, "lib.zip")
KEYSTORE_PATH = os.path.join(SCRIPT_DIR, "appmon.keystore")


def find_smali_folders(root_folder):
    """smali, smali_classes2, ... (multi-dex layout produced by apktool)."""
    smali_pattern = re.compile(r"^smali(_classes\d+)?$")
    smali_folders = []
    for root, dirs, files in os.walk(root_folder):
        for dir_name in dirs:
            if smali_pattern.match(dir_name):
                smali_folders.append(os.path.join(root, dir_name))
    return smali_folders


def load_nsc_text():
    nsc_path = os.path.join(SCRIPT_DIR, NSC_FILE_NAME)
    if os.path.isfile(nsc_path):
        with codecs.open(nsc_path, "r", "utf-8") as f:
            return f.read()
    return DEFAULT_NSC


def ensure_internet_permission(doc):
    """Insert <uses-permission android:name="android.permission.INTERNET"/>
    if the manifest lacks it. The frida-gadget listens on a TCP port, so an
    app without INTERNET gets a dead gadget. (The old implementation's
    permission-insert branch was dead code: it only fired when the
    permission line it searched for already existed.) Returns True if a
    permission was added.
    """
    android_idx = doc.android_ns_index()
    for node in doc.elements("uses-permission"):
        a = doc.find_android_attr(node, "name")
        if a is not None and a.ns == android_idx:
            if a.raw_value != NO_INDEX and doc.pool.strings[a.raw_value] == "android.permission.INTERNET":
                return False
    name_idx = doc.str_index("name")
    val_idx = doc.str_index("android.permission.INTERNET")
    perm_start = dict(
        kind=AxmlNode.START_ELEMENT,
        line=0,
        comment=NO_INDEX,
        ns=NO_INDEX,
        name=doc.str_index("uses-permission"),
        id_idx=0,
        class_idx=0,
        style_idx=0,
        attrs=[Attribute(android_idx, name_idx, val_idx, VAL_TYPE_STRING, val_idx)],
    )
    perm_end = dict(
        kind=AxmlNode.END_ELEMENT,
        line=0,
        comment=NO_INDEX,
        ns=NO_INDEX,
        name=doc.str_index("uses-permission"),
    )
    # doc.res_ids must map the "name" attr index to the framework id for the
    # same merge-walk reason as set_or_add_attr
    while len(doc.res_ids) < len(doc.pool.strings):
        doc.res_ids.append(0)
    doc.res_ids[name_idx] = ATTR_ID_NAME
    # manifest children: <application> must come last, so dropping the new
    # nodes right before it keeps the schema order regardless of what the
    # app shipped (activities/services sit between permissions and app too).
    insert_at = len(doc.nodes)
    for i, n in enumerate(doc.nodes):
        if n["kind"] == AxmlNode.START_ELEMENT and doc.pool.strings[n["name"]] == "application":
            insert_at = i
            break
    doc.nodes[insert_at:insert_at] = [perm_start, perm_end]
    return True


def apply_zip_surgery(apk_path, out_path, add_extract_native_libs=True):
    """Manifest/arsc patching without decoding anything (APKProxyHelper port).

    Adds to the target apk:
      * res/xml/network_security_config.xml (compiled debug NSC)
      * an resources.arsc entry so it resolves as @xml/network_security_config
      * manifest attrs on <application>: networkSecurityConfig,
        usesCleartextTraffic, debuggable (+ extractNativeLibs when the
        gadget stage runs, so System.loadLibrary finds the .so even if the
        original build shipped it uncompressed-unaligned)
      * <uses-permission android:name="android.permission.INTERNET"/> if missing
    """
    zin = zipfile.ZipFile(apk_path, "r")
    names = zin.namelist()
    if "AndroidManifest.xml" not in names or "resources.arsc" not in names:
        raise ValueError("not an APK: missing AndroidManifest.xml/resources.arsc")

    # -- arsc: make sure an @xml/network_security_config resource exists -----
    print("[I] Patching resources.arsc")
    arsc = ArscTable(zin.read("resources.arsc"))
    pkg = arsc.app_package()
    if pkg is None:
        raise ValueError("resources.arsc contains no resource packages")

    resid = None
    type_id = pkg.type_index("xml")
    if type_id > 0:
        for rid, path in pkg.entry_file_paths(type_id, arsc.global_pool).items():
            # startswith so re-runs over our own (or APKProxyHelper's)
            # suffixed entries reuse them instead of appending _appmon_appmon
            if os.path.basename(path).startswith(NSC_RES_NAME):
                resid = rid
                nsc_zip_path = path
                break
    if resid is not None:
        print("[I]     reusing existing resource 0x%08x (%s)" % (resid, nsc_zip_path))
    else:
        key = NSC_RES_NAME
        while key in pkg.key_pool.strings:
            key += "_appmon"
        path = "res/xml/%s.xml" % key
        while path in names:
            key += "_appmon"
            path = "res/xml/%s.xml" % key
        if type_id < 0:
            # register the "xml" type name; its type index = pool pos + 1
            type_id = pkg.type_pool.append("xml") + 1
        resid = pkg.append_file_entry(type_id, key, path, arsc.global_pool)
        nsc_zip_path = path
        print("[I]     added resource 0x%08x -> %s" % (resid, path))
    patched_arsc = arsc.serialize()
    nsc_payload = compile_xml_to_axml(load_nsc_text())

    # -- manifest: splice + sort attributes ----------------------------------
    print("[I] Patching AndroidManifest.xml")
    doc = AxmlDocument(zin.read("AndroidManifest.xml"))
    apps = list(doc.elements("application"))
    if not apps:
        raise ValueError("manifest has no <application> element")
    app = apps[0]
    raw_ref = "@xml/" + os.path.splitext(os.path.basename(nsc_zip_path))[0]
    if ensure_internet_permission(doc):
        print("[I]     added INTERNET permission")
    # All attrs required for reliable instrumentation:
    #  - networkSecurityConfig -> our debug NSC (trust user CAs for TLS)
    #  - usesCleartextTraffic  -> allows http://; okhttp consults this
    #    platform flag, and the NSC alone did NOT suffice in the manual
    #    HDO Box bypass
    #  - debuggable            -> activates the NSC <debug-overrides> and
    #    marks the pkgFlags [DEBUGGABLE] the bench checks for
    doc.set_or_add_attr(app, "networkSecurityConfig", VAL_TYPE_REFERENCE, resid, raw_ref)
    doc.set_or_add_attr(app, "usesCleartextTraffic", VAL_TYPE_BOOLEAN, BOOL_TRUE, "true")
    doc.set_or_add_attr(app, "debuggable", VAL_TYPE_BOOLEAN, BOOL_TRUE, "true")
    if add_extract_native_libs:
        doc.set_or_add_attr(app, "extractNativeLibs", VAL_TYPE_BOOLEAN, BOOL_TRUE, "true")
    patched_manifest = doc.serialize()

    # -- rezip: originals byte-for-byte, patched entries replaced ------------
    print("[I] Writing %s" % out_path)
    sig_suffixes = (".SF", ".RSA", ".DSA", ".EC")
    with zipfile.ZipFile(out_path, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if name.startswith("META-INF/") and (
                name == "META-INF/MANIFEST.MF" or name.endswith(sig_suffixes)
            ):
                continue  # stale signature artifacts
            if name == "AndroidManifest.xml":
                payload, method = patched_manifest, zipfile.ZIP_DEFLATED
            elif name == "resources.arsc":
                # API 30+ requires resources.arsc stored uncompressed
                payload, method = patched_arsc, zipfile.ZIP_STORED
            elif name == nsc_zip_path:
                payload, method = nsc_payload, zipfile.ZIP_DEFLATED
            else:
                payload, method = zin.read(name), info.compress_type
            zi = zipfile.ZipInfo(name, date_time=info.date_time)
            zi.compress_type = method
            zi.external_attr = info.external_attr
            zout.writestr(zi, payload)
        if nsc_zip_path not in names:
            zi = zipfile.ZipInfo(nsc_zip_path, date_time=(2024, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(zi, nsc_payload)
    zin.close()


def inject_gadget(apk_path, work_dir):
    """Embed the frida-gadget and load it from the launchable activity.

    Unchanged from the previous apk_builder flow (apktool decode -> smali
    patch -> libs -> apktool build) because dex-level edits still mean
    smali. Returns the path of the rebuilt (unsigned, unaligned) apk.
    Raises on any apktool failure - the caller falls back to manifest-only.
    """
    build_tools = find_build_tools()
    aapt = os.path.join(build_tools, "aapt")
    if not os.path.isfile(aapt):
        aapt = "aapt"

    print("[I] Reading apk metadata...")
    apk_dump = subprocess.check_output([aapt, "dump", "badging", apk_path]).decode()
    package_name = apk_dump.split("package: name=")[1].split(" ")[0].strip("'\"\n\t ")
    try:
        launchable_activity = (
            apk_dump.split("launchable-activity: name=")[1].split(" ")[0].strip("'\"\n\t ")
        )
    except IndexError:
        raise RuntimeError("No launchable activity found - cannot place gadget loader")

    stage1_apk = os.path.join(work_dir, "gadget_stage.apk")
    out_dir = os.path.join(work_dir, package_name)

    print("[I] Expanding APK (apktool)...")
    subprocess.check_call(["apktool", "d", "-f", apk_path, "-o", out_dir])

    # support for multi-dex
    launchable_activity_path = None
    for smali_class_folder in find_smali_folders(out_dir):
        candidate = os.path.join(
            smali_class_folder, launchable_activity.replace(".", "/") + ".smali"
        )
        if os.path.isfile(candidate):
            launchable_activity_path = candidate
    if launchable_activity_path is None:
        raise RuntimeError("No launchable activity found - cannot place gadget loader")

    print("[I] Searching .smali")
    with codecs.open(launchable_activity_path, "r", "utf-8") as f:
        file_contents = f.readlines()

    # Anchor the gadget loader to the class's static constructor. The original
    # APKProxyHelper heuristic injected into the FIRST direct method whenever
    # the class had no <clinit> - but in r8-minified apps the first direct
    # method is often a synthetic $r8$lambda$ helper whose registers are live.
    # The injected const-string v0 then clobbers a parameter and the class
    # dies at load with java.lang.VerifyError ("'this' argument String not
    # instance of <Activity>") - seen on PCAPdroid 1.6.5, whose MainActivity
    # sorts $r8$lambda$... before <init> ('%'/'$' sort before '<').
    if "Ljava/lang/System;->loadLibrary" in "".join(file_contents):
        print("[I] Gadget loader already present - skipping smali patch")
        regenerated_smali = "".join(file_contents)
    else:
        direct_start = None       # index of the "# direct methods" header
        direct_end = len(file_contents)  # index of "# virtual methods" or EOF
        for line in range(len(file_contents)):
            if "# direct methods" in file_contents[line]:
                direct_start = line
            elif "# virtual methods" in file_contents[line]:
                direct_end = line
                break
        if direct_start is None:
            raise RuntimeError(
                "No '# direct methods' section in %s" % launchable_activity_path
            )

        clinit_line = None
        for cursor in range(direct_start, direct_end):
            if (
                ".method" in file_contents[cursor]
                and "constructor <clinit>()V" in file_contents[cursor]
            ):
                clinit_line = cursor
                break

        if clinit_line is not None:
            # <clinit> exists: insert after its register declaration and
            # (when present) .prologue, so the loader lands before the first
            # instruction but after all directives.
            insert_at = None
            for cursor in range(clinit_line + 1, direct_end):
                l = file_contents[cursor]
                if ".end method" in l:
                    break
                if ".registers" in l or ".locals" in l:
                    insert_at = cursor + 1
                if ".prologue" in l:
                    insert_at = cursor + 1
                    break
            if insert_at is None:
                raise RuntimeError(
                    "<clinit> has no register directives - cannot place gadget loader"
                )
            file_contents[insert_at:insert_at] = [SMALI_PROLOGUE]
        else:
            # No <clinit>: append a fresh one right after the "# direct
            # methods" header. A static constructor owns its own registers
            # (nothing live to clobber) and runs before any activity code.
            file_contents[direct_start + 1:direct_start + 1] = [SMALI_DIRECT_METHODS]
        regenerated_smali = "".join(file_contents)

    print("[I] Patching .smali")
    with codecs.open(launchable_activity_path, "w", "utf-8") as f:
        f.write(regenerated_smali)

    print("[I] Injecting libs")
    lib_dir = os.path.join(out_dir, "lib")
    if not os.path.isdir(lib_dir):
        os.makedirs(lib_dir)
    if not os.path.isfile(LIB_FILE_PATH):
        raise RuntimeError("lib.zip (frida-gadget binaries) missing - run getlibs.sh")
    subprocess.run(["unzip", "-o", LIB_FILE_PATH, "-d", lib_dir], check=True)

    for abi_dir in os.listdir(lib_dir):
        abi_path = os.path.join(lib_dir, abi_dir)
        if os.path.isdir(abi_path):
            if os.path.isfile(os.path.join(abi_path, "libfrida-gadget.so")):
                print("[I]   + %s/libfrida-gadget.so" % abi_dir)

    print("[I] Building APK (apktool)...")
    meta_inf = os.path.join(out_dir, "original/META-INF")
    if os.path.exists(meta_inf):
        shutil.rmtree(meta_inf)
    subprocess.check_output(["apktool", "build", out_dir])

    built = os.path.join(out_dir, "dist", "%s.apk" % package_name)
    if not os.path.isfile(built):
        # apktool names the dist output after the SOURCE apk (apktool.yml
        # apkFileName), not the decode folder - so when the decode folder is
        # <package> the produced name differs. Glob rather than guess.
        candidates = glob.glob(os.path.join(out_dir, "dist", "*.apk"))
        if not candidates:
            raise RuntimeError("apktool build produced no APK under %s/dist" % out_dir)
        built = candidates[0]
    shutil.move(built, stage1_apk)
    return stage1_apk


def align_and_sign(apk_path, out_path):
    """zipalign + apksigner with the appmon keystore (same as previous flow)."""
    build_tools = find_build_tools()
    print("[I] Aligning APK")
    aligned = out_path + ".aligned"
    subprocess.check_output(
        [
            os.path.join(build_tools, "zipalign"),
            "-v", "-p", "-f", "4",
            apk_path, aligned,
        ]
    )
    align_verify = subprocess.check_output(
        [os.path.join(build_tools, "zipalign"), "-v", "-c", "4", aligned]
    ).decode()
    if "Verification succesful" not in align_verify and "Verification successful" not in align_verify:
        # (both spellings kept: the tool's historical check matches the old
        # zipalign typo)
        print("[E] alignment verification failed")
        sys.exit(1)
    print("[I] APK alignment verified")

    print("[I] Signing APK")
    if not os.path.isfile(KEYSTORE_PATH):
        print("[E] keystore not found: %s" % KEYSTORE_PATH)
        sys.exit(1)
    sign_status = subprocess.check_output(
        [
            os.path.join(build_tools, "apksigner"),
            "sign",
            "--verbose",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", "pass:appmon",
            "--out", out_path,
            aligned,
        ]
    ).decode()
    if "Signed" not in sign_status:
        print("[E] APK signing error %s" % sign_status)
        sys.exit(1)

    sign_verify = subprocess.check_output(
        [os.path.join(build_tools, "apksigner"), "verify", "--verbose", out_path]
    ).decode()
    if (
        "Verified using v1 scheme (JAR signing): true" not in sign_verify
        and "Verified using v2 scheme (APK Signature Scheme v2): true" not in sign_verify
    ):
        print(sign_verify)
    else:
        print("[I] APK signature verified")
    os.remove(aligned)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apk",
        action="store",
        dest="apk_path",
        default="",
        help="(absolute) path to APK",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        dest="manifest_only",
        help="skip frida-gadget injection (no apktool round-trip); "
        "only patch the manifest/arsc via zip surgery",
    )
    parser.add_argument(
        "--out",
        action="store",
        dest="out_path",
        default="",
        help="(optional) output path; default <orig-name>-appmon.apk in cwd",
    )
    parser.add_argument("-v", action="version", version="APK Builder v0.2 (zip-surgery manifest patching)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    results = parser.parse_args()
    apk_path = os.path.normpath(os.path.expanduser(results.apk_path))
    if not os.path.isfile(apk_path):
        print("[E] File doesn't exist: %s\n[*] Quitting!" % apk_path)
        sys.exit(1)

    if results.out_path:
        out_path = os.path.normpath(os.path.expanduser(results.out_path))
    else:
        out_path = os.path.join(
            os.getcwd(), os.path.basename(apk_path).split(".apk")[0] + "-appmon.apk"
        )

    work_dir = tempfile.mkdtemp(prefix="appmon_apk_")
    try:
        stage1_apk = apk_path
        if not results.manifest_only:
            try:
                stage1_apk = inject_gadget(apk_path, work_dir)
            except Exception as e:
                print("[W] Gadget injection failed (%s)" % e)
                print("[W] Falling back to manifest-only patching")
                stage1_apk = apk_path

        # extractNativeLibs only matters when the gadget ships inside the apk
        apply_zip_surgery(
            stage1_apk, out_path, add_extract_native_libs=not results.manifest_only
        )
        align_and_sign(out_path, out_path)

        if os.path.isfile(out_path):
            print("[I] Ready: %s" % out_path)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
