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

RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

# ResTable_type.flags (a uint8 at offset 9 - offset 10 is the reserved u16)
TYPE_FLAG_SPARSE = 0x01
TYPE_FLAG_OFFSET16 = 0x02

# ResTable_entry.flags
ENTRY_FLAG_COMPLEX = 0x0001
ENTRY_FLAG_COMPACT = 0x0008


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
        self.sorted = False
        self.strings = []  # decoded text, for lookups only - never re-encoded
        self._data = b""  # original string data region, verbatim
        self._offsets = []  # original string offsets into self._data
        self._appended = []  # encoded entries (lengths + data + NUL) to add
        self._style_offsets = []  # one per styled string, into self._styles
        self._styles = b""  # raw span block incl. END sentinels, kept verbatim
        self._flags_extra = 0  # unknown header flag bits, preserved

    @staticmethod
    def parse(data, off):
        pool = StringPool()
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, off)
        if chunk_type != RES_STRING_POOL_TYPE:
            raise ValueError("expected string pool chunk, got 0x%04x" % chunk_type)
        pool.size = chunk_size
        (str_count, style_count, flags, strings_start, styles_start) = struct.unpack_from(
            "<IIIII", data, off + 8
        )
        pool.utf8 = bool(flags & 0x100)
        pool.sorted = bool(flags & 0x1)
        pool._flags_extra = flags & ~0x101
        offsets = struct.unpack_from("<%dI" % str_count, data, off + header_size)
        # the style-offset array follows the string offsets (one byte offset
        # into the span block per styled string)
        pool._style_offsets = list(
            struct.unpack_from("<%dI" % style_count, data, off + header_size + 4 * str_count)
        )
        # Keep the string data region as-is rather than re-encoding each
        # string from its decoded text: aapt2 writes supplementary chars
        # (emoji) as modified-UTF-8 surrogate pairs that decode to U+FFFD
        # here, some producers emit non-canonical two-byte lengths (seen on
        # Telecel Play 26.10.2 / com.myvodafone.app, a bundletool universal
        # APK) and some share the bytes of identical strings (WireGuard's type
        # pool) - a re-encode silently rewrites the first two and duplicates
        # the last.
        if str_count > 0:
            region_end = styles_start if style_count > 0 else chunk_size
            pool._data = bytes(data[off + strings_start : off + region_end])
            pool._offsets = list(offsets)
        base = off + strings_start
        for o in offsets:
            if pool.utf8:
                _, p = StringPool._decode_len8(data, base + o)
                u8len, p = StringPool._decode_len8(data, p)
                text = bytes(data[p : p + u8len]).decode("utf-8", "replace")
            else:
                u16len, p = StringPool._decode_len16(data, base + o)
                text = bytes(data[p : p + 2 * u16len]).decode("utf-16-le", "replace")
            pool.strings.append(text)
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
        self._appended.append(self._encode_string(s))
        # an appended string breaks sort order; unsorted pools are always
        # legal (lookups fall back to a linear scan)
        self.sorted = False
        return len(self.strings) - 1

    def _encode_string(self, s):
        # aapt measures length in UTF-16 code units, not code points
        u16 = s.encode("utf-16-le")
        u16len = len(u16) // 2
        if self.utf8:
            raw = s.encode("utf-8")
            if max(u16len, len(raw)) > 0x7FFF:  # two-byte length limit
                raise ValueError("string too long for a UTF-8 pool: %r..." % s[:40])
            return self._encode_len8(u16len) + self._encode_len8(len(raw)) + raw + b"\x00"
        return self._encode_len16(u16len) + u16 + b"\x00\x00"

    def serialize(self):
        # aapt2 layout: header | string offsets | STYLE offsets | string data
        # | span block. The style-offset array is the easy one to lose: an
        # earlier revision dropped it, so the platform read style offsets out
        # of the string data and rejected the whole table ("Bad string block:
        # style offsets extend past style data start" / "RES_STRING_POOL_TYPE
        # corrupt" -> INSTALL_PARSE_FAILED_NOT_APK: Failed to load asset path)
        # for every app with a styled string resource.
        offsets = list(self._offsets)
        data = bytearray(self._data)
        for e in self._appended:
            offsets.append(len(data))
            data += e
        data += b"\x00" * (-len(data) % 4)  # spans need 4-byte alignment
        count = len(offsets)
        style_count = len(self._style_offsets)
        flags = self._flags_extra | (0x100 if self.utf8 else 0) | (0x1 if self.sorted else 0)
        strings_start = 28 + 4 * (count + style_count)
        if style_count > 0:
            styles_start = strings_start + len(data)
            # no tail padding: the span block must END the chunk - the
            # platform checks its last 12 bytes are the 0xFFFFFFFF sentinels
            chunk_size = styles_start + len(self._styles)
        else:
            styles_start = 0
            chunk_size = strings_start + len(data)
        out = bytearray(
            struct.pack(
                "<HHIIIIII",
                RES_STRING_POOL_TYPE,
                28,
                chunk_size,
                count,
                style_count,
                flags,
                strings_start,
                styles_start,
            )
        )
        out += struct.pack("<%dI" % count, *offsets)
        out += struct.pack("<%dI" % style_count, *self._style_offsets)
        out += data
        out += self._styles
        return bytes(out)


# ---------------------------------------------------------------------------
# Binary XML (AXML) editing: parse the manifest, splice attributes into
# <application>, re-serialize with a fresh string pool / resource map.
# Original string indices are preserved (pool rebuilt in order, appends only),
# so every untouched node and every style span keeps working.
# ---------------------------------------------------------------------------


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
            ext = off + chunk_hdr  # node payload follows the (16-byte) node header
            if chunk_type == 0x0001:
                self.pool = StringPool.parse(data, off)
            elif chunk_type == 0x0180:
                n = (chunk_size - chunk_hdr) // 4
                self.res_ids = list(struct.unpack_from("<%dI" % n, data, off + chunk_hdr))
            elif chunk_type in (AxmlNode.START_NS, AxmlNode.END_NS):
                prefix, uri = struct.unpack_from("<II", data, ext)
                self.nodes.append(
                    dict(kind=chunk_type, line=line, comment=comment, prefix=prefix, uri=uri)
                )
            elif chunk_type == AxmlNode.START_ELEMENT:
                ns, name = struct.unpack_from("<II", data, ext)
                attr_start, attr_size, attr_count, id_idx, class_idx, style_idx = struct.unpack_from(
                    "<HHHHHH", data, ext + 8
                )
                attrs = []
                abase = ext + attr_start
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
                ns, name = struct.unpack_from("<II", data, ext)
                self.nodes.append(dict(kind=chunk_type, line=line, comment=comment, ns=ns, name=name))
            elif chunk_type == AxmlNode.CDATA:
                # ResXMLTree_cdataExt: string ref + an 8-byte typed Res_value.
                # Dropping typedData leaves a node the platform rejects
                # ("Bad XML block: header type 0x104 ... has size 4, need 12").
                (cdata,) = struct.unpack_from("<I", data, ext)
                typed = bytes(data[ext + 4 : ext + 12])
                self.nodes.append(
                    dict(kind=chunk_type, line=line, comment=comment, data=cdata, typed=typed)
                )
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
            return self._node_header(n, 12) + struct.pack("<I", n["data"]) + n["typed"]
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


def _iter_chunks(data, start, end):
    """Yield (offset, type, raw bytes) for each chunk in data[start:end]."""
    c = start
    while c < end:
        ctype, chdr, csize = struct.unpack_from("<HHI", data, c)
        if chdr < 8 or chdr > csize or c + csize > end:
            raise ValueError("malformed chunk 0x%04x at offset %d" % (ctype, c))
        yield c, ctype, bytes(data[c : c + csize])
        c += csize


class ArscPackage:
    def __init__(self, data, off):
        (self.chunk_type, self.header_size, self.size, self.id) = struct.unpack_from(
            "<HHII", data, off
        )
        # fixed header kept verbatim (name, and typeIdOffset when present -
        # old aapt wrote 284-byte headers without it); serialize() patches
        # only the size and string-pool fields
        self.raw_header = bytes(data[off : off + self.header_size])
        (
            type_strings_off,
            self.last_public_type,
            key_strings_off,
            self.last_public_key,
        ) = struct.unpack_from("<IIII", data, off + 268)
        # Children: the type/key string pools - located by their header
        # offsets, exactly as LoadedPackage::Load does - and every other
        # chunk in original order. Type and type-spec chunks carry enough
        # parsed state to rebuild them; all chunks keep raw bytes, so
        # untouched ones (library, overlayable, staged-alias ...) are copied
        # verbatim.
        self.type_pool = self.key_pool = None
        self.chunks = []
        for c, ctype, raw in _iter_chunks(data, off + self.header_size, off + self.size):
            if c - off == type_strings_off:
                self.type_pool = StringPool.parse(data, c)
            elif c - off == key_strings_off:
                self.key_pool = StringPool.parse(data, c)
            elif ctype == RES_TABLE_TYPE_TYPE:
                self.chunks.append(self._parse_type_chunk(raw))
            elif ctype == RES_TABLE_TYPE_SPEC_TYPE:
                self.chunks.append(dict(kind=ctype, type_id=raw[8], raw=raw))
            else:
                self.chunks.append(dict(kind=ctype, raw=raw))
        if self.type_pool is None or self.key_pool is None:
            raise ValueError("package 0x%02x has no type/key string pool" % self.id)

    @staticmethod
    def _parse_type_chunk(raw):
        # ResTable_type: {hdr(8), u8 id, u8 flags, u16 reserved, u32
        # entryCount, u32 entriesStart} + ResTable_config up to headerSize.
        # flags is the u8 at offset 9: reading a u16 at offset 10 (as an
        # earlier revision did) hits the reserved field, so sparse/offset16
        # tables were walked as dense uint32 ones.
        entry_count, entries_start = struct.unpack_from("<II", raw, 12)
        return dict(
            kind=RES_TABLE_TYPE_TYPE,
            type_id=raw[8],
            flags=raw[9],
            header_size=struct.unpack_from("<H", raw, 2)[0],
            entry_count=entry_count,
            entries_start=entries_start,
            raw=raw,
        )

    def type_index(self, type_name):
        try:
            return self.type_pool.strings.index(type_name) + 1
        except ValueError:
            return -1

    def type_chunks(self, type_id):
        return [
            c
            for c in self.chunks
            if c["kind"] == RES_TABLE_TYPE_TYPE and c["type_id"] == type_id
        ]

    def type_spec(self, type_id):
        for c in self.chunks:
            if c["kind"] == RES_TABLE_TYPE_SPEC_TYPE and c["type_id"] == type_id:
                return c
        return None

    def _resid(self, type_id, entry_idx):
        return (self.id << 24) | (type_id << 16) | entry_idx

    @staticmethod
    def is_default_config(chunk):
        # default config = every qualifier byte zero. The config starts at
        # offset 20 with ResTable_config.size itself (always non-zero), so
        # compare only the qualifier payload after it.
        return not any(chunk["raw"][24 : chunk["header_size"]])

    @staticmethod
    def _iter_entries(chunk):
        """Yield (entry_index, byte offset from entriesStart) for present entries."""
        raw, hdr, n = chunk["raw"], chunk["header_size"], chunk["entry_count"]
        if chunk["flags"] & TYPE_FLAG_SPARSE:
            # entryCount ResTable_sparseTypeEntry {u16 idx, u16 offset / 4},
            # sorted by idx - entryCount counts PRESENT entries, not indices
            vals = struct.unpack_from("<%dH" % (2 * n), raw, hdr)
            for i in range(n):
                yield vals[2 * i], vals[2 * i + 1] * 4
        elif chunk["flags"] & TYPE_FLAG_OFFSET16:
            # one u16 per index: offset / 4, 0xFFFF = no entry
            for i, o in enumerate(struct.unpack_from("<%dH" % n, raw, hdr)):
                if o != 0xFFFF:
                    yield i, o * 4
        else:
            for i, o in enumerate(struct.unpack_from("<%dI" % n, raw, hdr)):
                if o != NO_INDEX:
                    yield i, o

    @staticmethod
    def _entry_value(raw, p):
        """(dataType, data) of the simple entry at raw[p], or None for bags."""
        esize, eflags = struct.unpack_from("<HH", raw, p)
        if eflags & ENTRY_FLAG_COMPACT:
            # compact entry (aapt2 --enable-compact-entries): {u16 key, u16
            # flags with the dataType in the high byte, u32 data}
            return (eflags >> 8, struct.unpack_from("<I", raw, p + 4)[0])
        if eflags & ENTRY_FLAG_COMPLEX:
            return None
        vsize, vres0, vtype, vdata = struct.unpack_from("<HBBI", raw, p + esize)
        return (vtype, vdata)

    def entry_file_paths(self, type_id, global_pool):
        """All file-backed entries of a type across every config chunk, as
        [(resource_id, file_path)] - one id can map to several files
        (res/xml/x.xml, res/xml-v24/x.xml ...)."""
        out = []
        for chunk in self.type_chunks(type_id):
            for i, off in self._iter_entries(chunk):
                value = self._entry_value(chunk["raw"], chunk["entries_start"] + off)
                if value and value[0] == VAL_TYPE_STRING:
                    out.append((self._resid(type_id, i), global_pool.strings[value[1]]))
        return out

    def append_file_entry(self, type_id, key_name, file_path, global_pool):
        """Add one file-backed resource to this package; return the resource id.

        The entry goes into the type's DEFAULT-config chunk (created if
        absent). The new entry index is one beyond the highest index used by
        the type spec or ANY config chunk of the type, so an exact-id lookup
        can never resolve to another config chunk that also happens to
        contain that index.
        """
        global_idx = global_pool.append(file_path)
        key_idx = self.key_pool.append(key_name)
        entry_idx = self._entry_index_bound(type_id)
        if entry_idx > 0xFFFF:
            raise ValueError("type 0x%02x has no free entry index" % type_id)

        spec = self.type_spec(type_id)
        new_type = spec is None
        if new_type:
            if self.type_chunks(type_id):
                raise ValueError("type 0x%02x has config chunks but no type spec" % type_id)
            # TYPE_SPEC: {hdr(8), u8 id, u8 res0, u16 typesCount, u32
            # entryCount} + per-entry flags (grown below). It must PRECEDE
            # the type's config chunks: LoadedPackage::Load rejects a type
            # chunk without an earlier spec of the same id.
            spec = dict(
                kind=RES_TABLE_TYPE_SPEC_TYPE,
                type_id=type_id,
                raw=struct.pack("<HHIBBHI", RES_TABLE_TYPE_SPEC_TYPE, 16, 16, type_id, 0, 1, 0),
            )
            self.chunks.append(spec)
        host = next((c for c in self.type_chunks(type_id) if self.is_default_config(c)), None)
        if host is None:
            host = self._new_default_type_chunk(type_id)
            # keep the type's chunks together, right after its last one
            last = max(i for i, c in enumerate(self.chunks) if c.get("type_id") == type_id)
            self.chunks.insert(last + 1, host)
            if not new_type:
                self._bump_types_count(spec)

        entry = struct.pack("<HHI", 8, 0, key_idx) + struct.pack(
            "<HBBI", 8, 0, VAL_TYPE_STRING, global_idx
        )
        self._add_entry(host, entry_idx, entry)
        self._grow_spec(spec, entry_idx + 1)

        self.last_public_type = max(self.last_public_type, type_id)
        self.last_public_key = max(self.last_public_key, key_idx)
        return self._resid(type_id, entry_idx)

    def _entry_index_bound(self, type_id):
        """One past the highest entry index the spec or any config chunk covers."""
        spec = self.type_spec(type_id)
        bound = struct.unpack_from("<I", spec["raw"], 12)[0] if spec else 0
        for chunk in self.type_chunks(type_id):
            if chunk["flags"] & TYPE_FLAG_SPARSE:
                # sparse entryCount counts present entries, not the index space
                bound = max([bound] + [i + 1 for i, _ in self._iter_entries(chunk)])
            else:
                bound = max(bound, chunk["entry_count"])
        return bound

    @staticmethod
    def _new_default_type_chunk(type_id):
        # An empty chunk for the default config: the 20-byte fixed header plus
        # a zeroed 64-byte ResTable_config whose leading size field says 64.
        # (An earlier revision emitted no config at all - a 20-byte header the
        # platform rejects as "RES_TABLE_TYPE_TYPE too small".)
        hdr = 20 + 64
        raw = struct.pack("<HHIBBHII", RES_TABLE_TYPE_TYPE, hdr, hdr, type_id, 0, 0, 0, hdr)
        raw += struct.pack("<I", 64) + b"\x00" * 60
        return ArscPackage._parse_type_chunk(raw)

    def _add_entry(self, chunk, entry_idx, entry_bytes):
        """Rebuild a type chunk in place with one more entry.

        Existing entry data is kept as one verbatim blob and only the offset
        table is rewritten, so entries are never re-encoded - compact,
        complex/bag or otherwise unusual entries survive untouched. Sparse
        and OFFSET16 tables are widened to the plain dense uint32 layout:
        valid on every API level and the simplest shape to extend; gaps
        become NO_INDEX holes (exactly what aapt emits for sparse key spaces).
        """
        raw, hdr = chunk["raw"], chunk["header_size"]
        offsets = dict(self._iter_entries(chunk))
        if entry_idx in offsets:
            raise ValueError("entry index %d already in use" % entry_idx)
        data = bytearray(raw[chunk["entries_start"] :])
        data += b"\x00" * (-len(data) % 4)  # entries must be 4-byte aligned
        offsets[entry_idx] = len(data)
        data += entry_bytes

        count = max(offsets) + 1
        if not chunk["flags"] & TYPE_FLAG_SPARSE:
            count = max(count, chunk["entry_count"])
        entries_start = hdr + 4 * count
        entries_start += (-entries_start) % 4
        out = bytearray(raw[:hdr])  # fixed header + ResTable_config, verbatim
        out[9] = chunk["flags"] & ~(TYPE_FLAG_SPARSE | TYPE_FLAG_OFFSET16)
        struct.pack_into("<II", out, 12, count, entries_start)
        out += struct.pack("<%dI" % count, *(offsets.get(i, NO_INDEX) for i in range(count)))
        out += b"\x00" * (entries_start - len(out))
        out += data
        out += b"\x00" * (-len(out) % 4)
        struct.pack_into("<I", out, 4, len(out))
        chunk.update(self._parse_type_chunk(bytes(out)))

    @staticmethod
    def _grow_spec(spec, count):
        # grow the per-entry flag array to `count` entries; rebuild the whole
        # chunk so the size field stays truthful (a stale size makes
        # aapt2/framework walk chunks misaligned)
        raw = spec["raw"]
        hdr = struct.unpack_from("<H", raw, 2)[0]
        n = struct.unpack_from("<I", raw, 12)[0]
        if n >= count:
            return
        out = bytearray(raw[: hdr + 4 * n]) + b"\x00" * (4 * (count - n))
        struct.pack_into("<I", out, 4, len(out))
        struct.pack_into("<I", out, 12, count)
        spec["raw"] = bytes(out)

    @staticmethod
    def _bump_types_count(spec):
        # ResTable_typeSpec.typesCount (u16 at offset 10, formerly reserved):
        # when non-zero it counts the type's config chunks
        raw = bytearray(spec["raw"])
        n = struct.unpack_from("<H", raw, 10)[0]
        if n:
            struct.pack_into("<H", raw, 10, n + 1)
            spec["raw"] = bytes(raw)

    def serialize(self):
        tp = self.type_pool.serialize()
        kp = self.key_pool.serialize()
        body = tp + kp + b"".join(c["raw"] for c in self.chunks)
        header = bytearray(self.raw_header)
        struct.pack_into("<I", header, 4, self.header_size + len(body))
        struct.pack_into(
            "<IIII",
            header,
            268,
            self.header_size,  # typeStrings starts right after the fixed header
            self.last_public_type,
            self.header_size + len(tp),  # keyStrings after the type pool
            self.last_public_key,
        )
        return bytes(header) + body


class ArscTable:
    def __init__(self, data):
        data = bytes(data)
        (chunk_type, self.header_size, size, self.package_count) = struct.unpack_from(
            "<HHII", data, 0
        )
        if chunk_type != RES_TABLE_TYPE:
            raise ValueError("not a resources.arsc table (type=0x%04x)" % chunk_type)
        self.raw_header = data[: self.header_size]
        # children in original order: the global string pool (the first pool,
        # as LoadedArsc uses), the packages, anything else verbatim
        self.global_pool = None
        self.packages = []
        self.children = []
        for c, ctype, raw in _iter_chunks(data, self.header_size, min(size, len(data))):
            if ctype == RES_STRING_POOL_TYPE and self.global_pool is None:
                child = self.global_pool = StringPool.parse(data, c)
            elif ctype == RES_TABLE_PACKAGE_TYPE:
                child = ArscPackage(data, c)
                self.packages.append(child)
            else:
                child = raw
            self.children.append(child)
        if self.global_pool is None:
            raise ValueError("resources.arsc has no global string pool")

    def app_package(self):
        # the manifest resolves refs against the app's own package (0x7f);
        # fall back to the first package for shared-library style tables
        for p in self.packages:
            if p.id == 0x7F:
                return p
        return self.packages[0] if self.packages else None

    def serialize(self):
        body = b"".join(c if isinstance(c, bytes) else c.serialize() for c in self.children)
        header = bytearray(self.raw_header)
        struct.pack_into("<I", header, 4, self.header_size + len(body))
        return bytes(header) + body


# ---------------------------------------------------------------------------




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
    files = pkg.entry_file_paths(type_id, arsc.global_pool) if type_id > 0 else []
    for rid, path in files:
        # startswith so re-runs over our own (or APKProxyHelper's)
        # suffixed entries reuse them instead of appending _appmon_appmon
        if os.path.basename(path).startswith(NSC_RES_NAME):
            resid = rid
            break
    if resid is not None:
        # every config variant (res/xml-v24/... etc.) gets the debug
        # config: a more specific variant left untouched wins at runtime
        nsc_zip_paths = sorted({path for rid, path in files if rid == resid})
        print("[I]     reusing existing resource 0x%08x (%s)" % (resid, ", ".join(nsc_zip_paths)))
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
        nsc_zip_paths = [path]
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
    raw_ref = "@xml/" + os.path.splitext(os.path.basename(nsc_zip_paths[0]))[0]
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
            elif name in nsc_zip_paths:
                payload, method = nsc_payload, zipfile.ZIP_DEFLATED
            else:
                payload, method = zin.read(name), info.compress_type
            zi = zipfile.ZipInfo(name, date_time=info.date_time)
            zi.compress_type = method
            zi.external_attr = info.external_attr
            zout.writestr(zi, payload)
        for path in nsc_zip_paths:
            if path not in names:
                zi = zipfile.ZipInfo(path, date_time=(2024, 1, 1, 0, 0, 0))
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
