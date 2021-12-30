#!/usr/bin/python3
# encoding: utf-8

# --                                                            ; {{{1
#
# File        : apksigcopier
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2021-04-14
#
# Copyright   : Copyright (C) 2021  Felix C. Stegerman
# Version     : v0.4.0
# License     : GPLv3+
#
# --                                                            ; }}}1

"""Copy/extract/patch apk signatures.

apksigcopier is a tool for copying APK signatures from a signed APK to an
unsigned one (in order to verify reproducible builds).


CLI
===

$ apksigcopier extract [OPTIONS] SIGNED_APK OUTPUT_DIR
$ apksigcopier patch [OPTIONS] METADATA_DIR UNSIGNED_APK OUTPUT_APK
$ apksigcopier copy [OPTIONS] SIGNED_APK UNSIGNED_APK OUTPUT_APK

The following environment variables can be set to 1, yes, or true to
overide the default behaviour:

* set APKSIGCOPIER_EXCLUDE_ALL_META=1 to exclude all metadata files
* set APKSIGCOPIER_COPY_EXTRA_BYTES=1 to copy extra bytes after data (e.g. a v2 sig)


API
===

>> from apksigcopier import do_extract, do_patch, do_copy
>> do_extract(signed_apk, output_dir, v1_only=NO)
>> do_patch(metadata_dir, unsigned_apk, output_apk, v1_only=NO)
>> do_copy(signed_apk, unsigned_apk, output_apk, v1_only=NO)

You can use False, None, and True instead of NO, AUTO, and YES respectively.

The following global variables (which default to False), can be set to
override the default behaviour:

* set exclude_all_meta=True to exclude all metadata files
* set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
"""

import glob
import os
import re
import struct
import sys
import zipfile
import zlib

from collections import namedtuple
from typing import Dict, Tuple, Union

__version__ = "0.4.0"
NAME = "apksigcopier"

SIGBLOCK, SIGOFFSET = "APKSigningBlock", "APKSigningBlockOffset"
NOAUTOYES = NO, AUTO, YES = ("no", "auto", "yes")
APK_META = re.compile(r"^META-INF/([0-9A-Za-z_-]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)$")
META_EXT = ("SF", "RSA|DSA|EC", "MF")
COPY_EXCLUDE = ("META-INF/MANIFEST.MF",)
DATETIMEZERO = (1980, 0, 0, 0, 0, 0)

ZipData = namedtuple("ZipData", ("cd_offset", "eocd_offset", "cd_and_eocd"))

copy_extra_bytes = False    # copy extra bytes after data in copy_apk()


class APKSigCopierError(Exception):
    """Base class for errors."""


class APKSigningBlockError(APKSigCopierError):
    """Something wrong with the APK Signing Block."""


class NoAPKSigningBlock(APKSigningBlockError):
    """APK Signing Block Missing."""


class ZipError(APKSigCopierError):
    """Something wrong with ZIP file."""


# FIXME: is there a better alternative?
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    _override = {}  # type: Dict[str, Union[int, Tuple[int, ...]]]

    def __init__(self, zinfo, **override):
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name):
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


class APKZipInfo(ReproducibleZipInfo):
    """Reproducible ZipInfo for APK files."""

    _override = dict(
        compress_type=8,
        create_system=0,
        create_version=20,
        date_time=DATETIMEZERO,
        external_attr=0,
        extract_version=20,
        flag_bits=0x800,
    )


def noautoyes(value):
    """Turn False into NO, None into AUTO, and True into YES.

    >>> from apksigcopier import noautoyes, NO, AUTO, YES
    >>> noautoyes(False) == NO == noautoyes(NO)
    True
    >>> noautoyes(None) == AUTO == noautoyes(AUTO)
    True
    >>> noautoyes(True) == YES == noautoyes(YES)
    True

    """
    if isinstance(value, str):
        if value not in NOAUTOYES:
            raise ValueError("expected NO, AUTO, or YES")
        return value
    try:
        return {False: NO, None: AUTO, True: YES}[value]
    except KeyError:
        raise ValueError("expected False, None, or True")


def is_meta(filename):
    """No summary.

    Returns whether filename is a v1 (JAR) signature file (.SF), signature block
    file (.RSA, .DSA, or .EC), or manifest (MANIFEST.MF).

    See https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
    """
    return APK_META.fullmatch(filename) is not None


def exclude_from_copying(filename):
    """Fdroidserver always wants JAR Signature files to be excluded."""
    return is_meta(filename)


################################################################################
#
# https://en.wikipedia.org/wiki/ZIP_(file_format)
# https://source.android.com/security/apksigning/v2#apk-signing-block-format
#
# =================================
# | Contents of ZIP entries       |
# =================================
# | APK Signing Block             |
# | ----------------------------- |
# | | size (w/o this) uint64 LE | |
# | | ...                       | |
# | | size (again)    uint64 LE | |
# | | "APK Sig Block 42" (16B)  | |
# | ----------------------------- |
# =================================
# | ZIP Central Directory         |
# =================================
# | ZIP End of Central Directory  |
# | ----------------------------- |
# | | 0x06054b50 ( 4B)          | |
# | | ...        (12B)          | |
# | | CD Offset  ( 4B)          | |
# | | ...                       | |
# | ----------------------------- |
# =================================
#
################################################################################


# FIXME: makes certain assumptions and doesn't handle all valid ZIP files!
def copy_apk(unsigned_apk, output_apk):
    """Copy APK like apksigner would, excluding files matched by exclude_from_copying().

    The following global variables (which default to False), can be set to
    override the default behaviour:

    * set exclude_all_meta=True to exclude all metadata files
    * set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)

    Returns
    -------
    max date_time.
    """
    with zipfile.ZipFile(unsigned_apk, "r") as zf:
        infos = zf.infolist()
    zdata = zip_data(unsigned_apk)
    offsets = {}
    with open(unsigned_apk, "rb") as fhi, open(output_apk, "w+b") as fho:
        for info in sorted(infos, key=lambda info: info.header_offset):
            off_i = fhi.tell()
            if info.header_offset > off_i:
                # copy extra bytes
                fho.write(fhi.read(info.header_offset - off_i))
            hdr = fhi.read(30)
            if hdr[:4] != b"\x50\x4b\x03\x04":
                raise ZipError("Expected local file header signature")
            n, m = struct.unpack("<HH", hdr[26:30])
            hdr += fhi.read(n + m)
            skip = exclude_from_copying(info.filename)
            if skip:
                fhi.seek(info.compress_size, os.SEEK_CUR)
            else:
                if info.filename in offsets:
                    raise ZipError("Duplicate ZIP entry: " + info.filename)
                offsets[info.filename] = off_o = fho.tell()
                if info.compress_type == 0 and off_o != info.header_offset:
                    hdr = _realign_zip_entry(info, hdr, n, m, off_o)
                fho.write(hdr)
                _copy_bytes(fhi, fho, info.compress_size)
            if info.flag_bits & 0x08:
                data_descriptor = fhi.read(12)
                if data_descriptor[:4] == b"\x50\x4b\x07\x08":
                    data_descriptor += fhi.read(4)
                if not skip:
                    fho.write(data_descriptor)
        extra_bytes = zdata.cd_offset - fhi.tell()
        if copy_extra_bytes:
            _copy_bytes(fhi, fho, extra_bytes)
        else:
            fhi.seek(extra_bytes, os.SEEK_CUR)
        cd_offset = fho.tell()
        for info in infos:
            hdr = fhi.read(46)
            if hdr[:4] != b"\x50\x4b\x01\x02":
                raise ZipError("Expected central directory file header signature")
            n, m, k = struct.unpack("<HHH", hdr[28:34])
            hdr += fhi.read(n + m + k)
            if not exclude_from_copying(info.filename):
                off = int.to_bytes(offsets[info.filename], 4, "little")
                hdr = hdr[:42] + off + hdr[46:]
                fho.write(hdr)
        eocd_offset = fho.tell()
        fho.write(zdata.cd_and_eocd[zdata.eocd_offset - zdata.cd_offset:])
        fho.seek(eocd_offset + 8)
        fho.write(struct.pack("<HHLL", len(offsets), len(offsets),
                              eocd_offset - cd_offset, cd_offset))
    return max(info.date_time for info in infos)


# NB: doesn't sync local & CD headers!
def _realign_zip_entry(info, hdr, n, m, off_o):
    align = 4096 if info.filename.endswith(".so") else 4
    old_off = 30 + n + m + info.header_offset
    new_off = 30 + n + m + off_o
    old_xtr = info.extra
    new_xtr = b""
    while len(old_xtr) >= 4:
        hdr_id, size = struct.unpack("<HH", old_xtr[:4])
        if size > len(old_xtr) - 4:
            break
        if not (hdr_id == 0 and size == 0):
            if hdr_id == 0xd935:
                if size >= 2:
                    align = int.from_bytes(old_xtr[4:6], "little")
            else:
                new_xtr += old_xtr[:size + 4]
        old_xtr = old_xtr[size + 4:]
    if old_off % align == 0 and new_off % align != 0:
        pad = (align - (new_off - m + len(new_xtr) + 6) % align) % align
        xtr = new_xtr + struct.pack("<HHH", 0xd935, 2 + pad, align) + pad * b"\x00"
        m_b = int.to_bytes(len(xtr), 2, "little")
        hdr = hdr[:28] + m_b + hdr[30:30 + n] + xtr
    return hdr


def _copy_bytes(fhi, fho, size, blocksize=4096):
    while size > 0:
        data = fhi.read(min(size, blocksize))
        if not data:
            break
        size -= len(data)
        fho.write(data)
    if size != 0:
        raise ZipError("Unexpected EOF")


def extract_meta(signed_apk):
    """
    Extract v1 signature metadata files from signed APK.

    Yields (ZipInfo, data) pairs.
    """
    with zipfile.ZipFile(signed_apk, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.filename):
                yield info, zf_sig.read(info.filename)


def patch_meta(extracted_meta, output_apk, date_time=DATETIMEZERO):
    """Add v1 signature metadata to APK (removes v2 sig block, if any)."""
    with zipfile.ZipFile(output_apk, "r") as zf_out:
        for info in zf_out.infolist():
            if is_meta(info.filename):
                raise ZipError("Unexpected metadata")
    with zipfile.ZipFile(output_apk, "a") as zf_out:
        info_data = [(APKZipInfo(info, date_time=date_time), data)
                     for info, data in extracted_meta]
        _write_to_zip(info_data, zf_out)


if sys.version_info >= (3, 7):
    def _write_to_zip(info_data, zf_out):
        for info, data in info_data:
            zf_out.writestr(info, data, compresslevel=9)
else:
    def _write_to_zip(info_data, zf_out):
        old = zipfile._get_compressor
        zipfile._get_compressor = lambda _: zlib.compressobj(9, 8, -15)
        try:
            for info, data in info_data:
                zf_out.writestr(info, data)
        finally:
            zipfile._get_compressor = old


def extract_v2_sig(apkfile, expected=True):
    """
    Extract APK Signing Block and offset from APK.

    When successful, returns (sb_offset, sig_block); otherwise raises
    NoAPKSigningBlock when expected is True, else returns None.
    """
    cd_offset = zip_data(apkfile).cd_offset
    with open(apkfile, "rb") as fh:
        fh.seek(cd_offset - 16)
        if fh.read(16) != b"APK Sig Block 42":
            if expected:
                raise NoAPKSigningBlock("No APK Signing Block")
            return None
        fh.seek(-24, os.SEEK_CUR)
        sb_size2 = int.from_bytes(fh.read(8), "little")
        fh.seek(-sb_size2 + 8, os.SEEK_CUR)
        sb_size1 = int.from_bytes(fh.read(8), "little")
        if sb_size1 != sb_size2:
            raise APKSigningBlockError("APK Signing Block sizes not equal")
        fh.seek(-8, os.SEEK_CUR)
        sb_offset = fh.tell()
        sig_block = fh.read(sb_size2 + 8)
    return sb_offset, sig_block


def zip_data(apkfile, count=1024):
    """
    Extract central directory, EOCD, and offsets from ZIP.

    Returns
    -------
    ZipData
    """
    with open(apkfile, "rb") as fh:
        fh.seek(-count, os.SEEK_END)
        data = fh.read()
        pos = data.rfind(b"\x50\x4b\x05\x06")
        if pos == -1:
            raise ZipError("Expected end of central directory record (EOCD)")
        fh.seek(pos - len(data), os.SEEK_CUR)
        eocd_offset = fh.tell()
        fh.seek(16, os.SEEK_CUR)
        cd_offset = int.from_bytes(fh.read(4), "little")
        fh.seek(cd_offset)
        cd_and_eocd = fh.read()
    return ZipData(cd_offset, eocd_offset, cd_and_eocd)


# FIXME: can we determine signed_sb_offset?
def patch_v2_sig(extracted_v2_sig, output_apk):
    """Implant extracted v2/v3 signature into APK."""
    signed_sb_offset, signed_sb = extracted_v2_sig
    data_out = zip_data(output_apk)
    if signed_sb_offset < data_out.cd_offset:
        raise APKSigningBlockError("APK Signing Block offset < central directory offset")
    padding = b"\x00" * (signed_sb_offset - data_out.cd_offset)
    offset = len(signed_sb) + len(padding)
    with open(output_apk, "r+b") as fh:
        fh.seek(data_out.cd_offset)
        fh.write(padding)
        fh.write(signed_sb)
        fh.write(data_out.cd_and_eocd)
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


def patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk):
    """Patch extracted_meta + extracted_v2_sig.

    Patches extracted_meta + extracted_v2_sig (if not None)
    onto unsigned_apk and save as output_apk.
    """
    date_time = copy_apk(unsigned_apk, output_apk)
    patch_meta(extracted_meta, output_apk, date_time=date_time)
    if extracted_v2_sig is not None:
        patch_v2_sig(extracted_v2_sig, output_apk)


def do_extract(signed_apk, output_dir, v1_only=NO):
    """Extract signatures from signed_apk and save in output_dir.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:

    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = tuple(extract_meta(signed_apk))
    if len(extracted_meta) not in (len(META_EXT), 0):
        raise APKSigCopierError("Unexpected or missing metadata files in signed_apk")
    for info, data in extracted_meta:
        name = os.path.basename(info.filename)
        with open(os.path.join(output_dir, name), "wb") as fh:
            fh.write(data)
    if v1_only == YES:
        if not extracted_meta:
            raise APKSigCopierError("Expected v1 signature")
        return
    expected = v1_only == NO
    extracted_v2_sig = extract_v2_sig(signed_apk, expected=expected)
    if extracted_v2_sig is None:
        if not extracted_meta:
            raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
        return
    signed_sb_offset, signed_sb = extracted_v2_sig
    with open(os.path.join(output_dir, SIGOFFSET), "w") as fh:
        fh.write(str(signed_sb_offset) + "\n")
    with open(os.path.join(output_dir, SIGBLOCK), "wb") as fh:
        fh.write(signed_sb)


def do_patch(metadata_dir, unsigned_apk, output_apk, v1_only=NO):
    """Patch signatures from metadata_dir onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:

    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = []
    for pat in META_EXT:
        files = [fn for ext in pat.split("|") for fn in
                 glob.glob(os.path.join(metadata_dir, "*." + ext))]
        if len(files) != 1:
            continue
        info = zipfile.ZipInfo("META-INF/" + os.path.basename(files[0]))
        with open(files[0], "rb") as fh:
            extracted_meta.append((info, fh.read()))
    if len(extracted_meta) not in (len(META_EXT), 0):
        raise APKSigCopierError("Unexpected or missing files in metadata_dir")
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        sigoffset_file = os.path.join(metadata_dir, SIGOFFSET)
        sigblock_file = os.path.join(metadata_dir, SIGBLOCK)
        if v1_only == AUTO and not os.path.exists(sigblock_file):
            extracted_v2_sig = None
        else:
            with open(sigoffset_file, "r") as fh:
                signed_sb_offset = int(fh.read())
            with open(sigblock_file, "rb") as fh:
                signed_sb = fh.read()
            extracted_v2_sig = signed_sb_offset, signed_sb
    if not extracted_meta and extracted_v2_sig is None:
        raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk)


def do_copy(signed_apk, unsigned_apk, output_apk, v1_only=NO):
    """Copy signatures from signed_apk onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:

    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = extract_meta(signed_apk)
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        extracted_v2_sig = extract_v2_sig(signed_apk, expected=v1_only == NO)
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
