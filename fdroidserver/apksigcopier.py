#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# --                                                            ; {{{1
#
# File        : apksigcopier
# Maintainer  : FC Stegerman <flx@obfusk.net>
# Date        : 2023-02-08
#
# Copyright   : Copyright (C) 2023  FC Stegerman
# Version     : v1.1.1
# License     : GPLv3+
#
# --                                                            ; }}}1

"""
Copy/extract/patch android apk signatures & compare apks.

apksigcopier is a tool for copying android APK signatures from a signed APK to
an unsigned one (in order to verify reproducible builds).

It can also be used to compare two APKs with different signatures; this requires
apksigner.


CLI
===

$ apksigcopier extract [OPTIONS] SIGNED_APK OUTPUT_DIR
$ apksigcopier patch [OPTIONS] METADATA_DIR UNSIGNED_APK OUTPUT_APK
$ apksigcopier copy [OPTIONS] SIGNED_APK UNSIGNED_APK OUTPUT_APK
$ apksigcopier compare [OPTIONS] FIRST_APK SECOND_APK

The following environment variables can be set to 1, yes, or true to
override the default behaviour:

* set APKSIGCOPIER_EXCLUDE_ALL_META=1 to exclude all metadata files
* set APKSIGCOPIER_COPY_EXTRA_BYTES=1 to copy extra bytes after data (e.g. a v2 sig)
* set APKSIGCOPIER_SKIP_REALIGNMENT=1 to skip realignment of ZIP entries


API
===

>> from apksigcopier import do_extract, do_patch, do_copy, do_compare
>> do_extract(signed_apk, output_dir, v1_only=NO)
>> do_patch(metadata_dir, unsigned_apk, output_apk, v1_only=NO)
>> do_copy(signed_apk, unsigned_apk, output_apk, v1_only=NO)
>> do_compare(first_apk, second_apk, unsigned=False)

You can use False, None, and True instead of NO, AUTO, and YES respectively.

The following global variables (which default to False), can be set to
override the default behaviour:

* set exclude_all_meta=True to exclude all metadata files
* set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
* set skip_realignment=True to skip realignment of ZIP entries
"""

import glob
import json
import os
import re
import struct
import sys
import zipfile
import zlib

from collections import namedtuple
from typing import Any, BinaryIO, Callable, Dict, Iterable, Iterator, Optional, Tuple, Union

__version__ = "1.1.1"
NAME = "apksigcopier"

if sys.version_info >= (3, 8):
    from typing import Literal
    NoAutoYes = Literal["no", "auto", "yes"]
else:
    NoAutoYes = str

DateTime = Tuple[int, int, int, int, int, int]
NoAutoYesBoolNone = Union[NoAutoYes, bool, None]
ZipInfoDataPairs = Iterable[Tuple[zipfile.ZipInfo, bytes]]

SIGBLOCK, SIGOFFSET = "APKSigningBlock", "APKSigningBlockOffset"
NOAUTOYES: Tuple[NoAutoYes, NoAutoYes, NoAutoYes] = ("no", "auto", "yes")
NO, AUTO, YES = NOAUTOYES
APK_META = re.compile(r"^META-INF/([0-9A-Za-z_-]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)$")
META_EXT: Tuple[str, ...] = ("SF", "RSA|DSA|EC", "MF")
COPY_EXCLUDE: Tuple[str, ...] = ("META-INF/MANIFEST.MF",)
DATETIMEZERO: DateTime = (1980, 0, 0, 0, 0, 0)

################################################################################
#
# NB: these values are all from apksigner (the first element of each tuple, same
# as APKZipInfo) or signflinger/zipflinger, except for external_attr w/ 0664
# permissions and flag_bits 0x08, added for completeness.
#
# NB: zipflinger changed from 0666 to 0644 in commit 895ba5fba6ab84617dd67e38f456a8f96aa37ff0
#
# https://android.googlesource.com/platform/tools/apksig
#   src/main/java/com/android/apksig/internal/zip/{CentralDirectoryRecord,LocalFileRecord,ZipUtils}.java
# https://android.googlesource.com/platform/tools/base
#   signflinger/src/com/android/signflinger/SignedApk.java
#   zipflinger/src/com/android/zipflinger/{CentralDirectoryRecord,LocalFileHeader,Source}.java
#
################################################################################

VALID_ZIP_META = dict(
    compresslevel=(9, 1),               # best compression, best speed
    create_system=(0, 3),               # fat, unx
    create_version=(20, 0),             # 2.0, 0.0
    external_attr=(0,                   # N/A
                   0o100644 << 16,      # regular file rw-r--r--
                   0o100664 << 16,      # regular file rw-rw-r--
                   0o100666 << 16),     # regular file rw-rw-rw-
    extract_version=(20, 0),            # 2.0, 0.0
    flag_bits=(0x800, 0, 0x08, 0x808),  # 0x800 = utf8, 0x08 = data_descriptor
)

ZipData = namedtuple("ZipData", ("cd_offset", "eocd_offset", "cd_and_eocd"))

exclude_all_meta = False    # exclude all metadata files in copy_apk()
copy_extra_bytes = False    # copy extra bytes after data in copy_apk()
skip_realignment = False    # skip realignment of ZIP entries in copy_apk()


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

    _override: Dict[str, Any] = {}

    def __init__(self, zinfo: zipfile.ZipInfo, **override: Any) -> None:
        # pylint: disable=W0231
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name: str) -> Any:
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


# See VALID_ZIP_META
class APKZipInfo(ReproducibleZipInfo):
    """Reproducible ZipInfo for APK files."""

    COMPRESSLEVEL = 9

    _override = dict(
        compress_type=8,
        create_system=0,
        create_version=20,
        date_time=DATETIMEZERO,
        external_attr=0,
        extract_version=20,
        flag_bits=0x800,
    )


def noautoyes(value: NoAutoYesBoolNone) -> NoAutoYes:
    """
    Turn False into NO, None into AUTO, and True into YES.

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
        raise ValueError("expected False, None, or True")   # pylint: disable=W0707


def is_meta(filename: str) -> bool:
    """
    Check whether filename is a JAR metadata file.

    Returns whether filename is a v1 (JAR) signature file (.SF), signature block
    file (.RSA, .DSA, or .EC), or manifest (MANIFEST.MF).

    See https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html

    >>> from apksigcopier import is_meta
    >>> is_meta("classes.dex")
    False
    >>> is_meta("META-INF/CERT.SF")
    True
    >>> is_meta("META-INF/CERT.RSA")
    True
    >>> is_meta("META-INF/MANIFEST.MF")
    True
    >>> is_meta("META-INF/OOPS")
    False

    """
    return APK_META.fullmatch(filename) is not None


def exclude_from_copying(filename: str) -> bool:
    """
    Check whether to exclude a file during copy_apk().

    Excludes filenames in COPY_EXCLUDE (i.e. MANIFEST.MF) by default; when
    exclude_all_meta is set to True instead, excludes all metadata files as
    matched by is_meta().

    Directories are always excluded.

    >>> import apksigcopier
    >>> from apksigcopier import exclude_from_copying
    >>> exclude_from_copying("classes.dex")
    False
    >>> exclude_from_copying("foo/")
    True
    >>> exclude_from_copying("META-INF/")
    True
    >>> exclude_from_copying("META-INF/MANIFEST.MF")
    True
    >>> exclude_from_copying("META-INF/CERT.SF")
    False
    >>> exclude_from_copying("META-INF/OOPS")
    False

    >>> apksigcopier.exclude_all_meta = True
    >>> exclude_from_copying("classes.dex")
    False
    >>> exclude_from_copying("META-INF/")
    True
    >>> exclude_from_copying("META-INF/MANIFEST.MF")
    True
    >>> exclude_from_copying("META-INF/CERT.SF")
    True
    >>> exclude_from_copying("META-INF/OOPS")
    False

    """
    return exclude_meta(filename) if exclude_all_meta else exclude_default(filename)


def exclude_default(filename: str) -> bool:
    """
    Like exclude_from_copying().

    Excludes directories and filenames in COPY_EXCLUDE (i.e. MANIFEST.MF).
    """
    return is_directory(filename) or filename in COPY_EXCLUDE


def exclude_meta(filename: str) -> bool:
    """Like exclude_from_copying(); excludes directories and all metadata files."""
    return is_directory(filename) or is_meta(filename)


def is_directory(filename: str) -> bool:
    """ZIP entries with filenames that end with a '/' are directories."""
    return filename.endswith("/")


################################################################################
#
# There is usually a 132-byte virtual entry at the start of an APK signed with a
# v1 signature by signflinger/zipflinger; almost certainly this is a default
# manifest ZIP entry created at initialisation, deleted (from the CD but not
# from the file) during v1 signing, and eventually replaced by a virtual entry.
#
#   >>> (30 + len("META-INF/MANIFEST.MF") +
#   ...       len("Manifest-Version: 1.0\r\n"
#   ...           "Created-By: Android Gradle 7.1.3\r\n"
#   ...           "Built-By: Signflinger\r\n\r\n"))
#   132
#
# NB: they could be a different size, depending on Created-By and Built-By.
#
# FIXME: could virtual entries occur elsewhere as well?
#
# https://android.googlesource.com/platform/tools/base
#   signflinger/src/com/android/signflinger/SignedApk.java
#   zipflinger/src/com/android/zipflinger/{LocalFileHeader,ZipArchive}.java
#
################################################################################

def zipflinger_virtual_entry(size: int) -> bytes:
    """Create zipflinger virtual entry."""
    if size < 30:
        raise ValueError("Minimum size for virtual entries is 30 bytes")
    return (
        # header            extract_version     flag_bits
        b"\x50\x4b\x03\x04" b"\x00\x00"         b"\x00\x00"
        # compress_type     (1981,1,1,1,1,2)    crc32
        b"\x00\x00"         b"\x21\x08\x21\x02" b"\x00\x00\x00\x00"
        # compress_size     file_size           filename length
        b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00"
    ) + int.to_bytes(size - 30, 2, "little") + b"\x00" * (size - 30)


def detect_zfe(apkfile: str) -> Optional[int]:
    """
    Detect zipflinger virtual entry.

    Returns the size of the virtual entry if found, None otherwise.

    Raises ZipError if the size is less than 30 or greater than 4096, or the
    data isn't all zeroes.
    """
    with open(apkfile, "rb") as fh:
        zfe_start = zipflinger_virtual_entry(30)[:28]   # w/o len(extra)
        if fh.read(28) == zfe_start:
            zfe_size = 30 + int.from_bytes(fh.read(2), "little")
            if not (30 <= zfe_size <= 4096):
                raise ZipError("Unsupported virtual entry size")
            if not fh.read(zfe_size - 30) == b"\x00" * (zfe_size - 30):
                raise ZipError("Unsupported virtual entry data")
            return zfe_size
    return None


################################################################################
#
# https://en.wikipedia.org/wiki/ZIP_(file_format)
# https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block-format
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
# FIXME: support zip64?
# FIXME: handle utf8 filenames w/o utf8 flag (as produced by zipflinger)?
# https://android.googlesource.com/platform/tools/apksig
#   src/main/java/com/android/apksig/ApkSigner.java
def copy_apk(unsigned_apk: str, output_apk: str, *,
             copy_extra: Optional[bool] = None,
             exclude: Optional[Callable[[str], bool]] = None,
             realign: Optional[bool] = None,
             zfe_size: Optional[int] = None) -> DateTime:
    """
    Copy APK like apksigner would, excluding files matched by exclude_from_copying().

    Adds a zipflinger virtual entry of zfe_size bytes if one is not already
    present and zfe_size is not None.

    Returns max date_time.

    The following global variables (which default to False), can be set to
    override the default behaviour:

    * set exclude_all_meta=True to exclude all metadata files
    * set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
    * set skip_realignment=True to skip realignment of ZIP entries

    The default behaviour can also be changed using the keyword-only arguments
    exclude, copy_extra, and realign; these take precedence over the global
    variables when not None.  NB: exclude is a callable, not a bool; realign is
    the inverse of skip_realignment.

    >>> import apksigcopier, os, zipfile
    >>> apk = "test/apks/apks/golden-aligned-in.apk"
    >>> with zipfile.ZipFile(apk, "r") as zf:
    ...     infos_in = zf.infolist()
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     apksigcopier.copy_apk(apk, out)
    ...     with zipfile.ZipFile(out, "r") as zf:
    ...         infos_out = zf.infolist()
    (2017, 5, 15, 11, 28, 40)
    >>> for i in infos_in:
    ...     print(i.filename)
    META-INF/
    META-INF/MANIFEST.MF
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> for i in infos_out:
    ...     print(i.filename)
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> infos_in[2]
    <ZipInfo filename='AndroidManifest.xml' compress_type=deflate file_size=1672 compress_size=630>
    >>> infos_out[0]
    <ZipInfo filename='AndroidManifest.xml' compress_type=deflate file_size=1672 compress_size=630>
    >>> repr(infos_in[2:]) == repr(infos_out)
    True

    """
    if copy_extra is None:
        copy_extra = copy_extra_bytes
    if exclude is None:
        exclude = exclude_from_copying
    if realign is None:
        realign = not skip_realignment
    with zipfile.ZipFile(unsigned_apk, "r") as zf:
        infos = zf.infolist()
    zdata = zip_data(unsigned_apk)
    offsets = {}
    with open(unsigned_apk, "rb") as fhi, open(output_apk, "w+b") as fho:
        if zfe_size:
            zfe = zipflinger_virtual_entry(zfe_size)
            if fhi.read(zfe_size) != zfe:
                fho.write(zfe)
            fhi.seek(0)
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
            skip = exclude(info.filename)
            if skip:
                fhi.seek(info.compress_size, os.SEEK_CUR)
            else:
                if info.filename in offsets:
                    raise ZipError(f"Duplicate ZIP entry: {info.filename!r}")
                offsets[info.filename] = off_o = fho.tell()
                if realign and info.compress_type == 0 and off_o != info.header_offset:
                    hdr = _realign_zip_entry(info, hdr, n, m, off_o,
                                             pad_like_apksigner=not zfe_size)
                fho.write(hdr)
                _copy_bytes(fhi, fho, info.compress_size)
            if info.flag_bits & 0x08:
                data_descriptor = fhi.read(12)
                if data_descriptor[:4] == b"\x50\x4b\x07\x08":
                    data_descriptor += fhi.read(4)
                if not skip:
                    fho.write(data_descriptor)
        extra_bytes = zdata.cd_offset - fhi.tell()
        if copy_extra:
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
            if not exclude(info.filename):
                off = int.to_bytes(offsets[info.filename], 4, "little")
                hdr = hdr[:42] + off + hdr[46:]
                fho.write(hdr)
        eocd_offset = fho.tell()
        fho.write(zdata.cd_and_eocd[zdata.eocd_offset - zdata.cd_offset:])
        fho.seek(eocd_offset + 8)
        fho.write(struct.pack("<HHLL", len(offsets), len(offsets),
                              eocd_offset - cd_offset, cd_offset))
    return max(info.date_time for info in infos if info.filename in offsets)


# NB: doesn't sync local & CD headers!
def _realign_zip_entry(info: zipfile.ZipInfo, hdr: bytes, n: int, m: int,
                       off_o: int, pad_like_apksigner: bool = True) -> bytes:
    align = 4096 if info.filename.endswith(".so") else 4
    old_off = 30 + n + m + info.header_offset
    new_off = 30 + n + m + off_o
    old_xtr = hdr[30 + n:30 + n + m]
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
        if pad_like_apksigner:
            pad = (align - (new_off - m + len(new_xtr) + 6) % align) % align
            xtr = new_xtr + struct.pack("<HHH", 0xd935, 2 + pad, align) + pad * b"\x00"
        else:
            pad = (align - (new_off - m + len(new_xtr)) % align) % align
            xtr = new_xtr + pad * b"\x00"
        m_b = int.to_bytes(len(xtr), 2, "little")
        hdr = hdr[:28] + m_b + hdr[30:30 + n] + xtr
    return hdr


def _copy_bytes(fhi: BinaryIO, fho: BinaryIO, size: int, blocksize: int = 4096) -> None:
    while size > 0:
        data = fhi.read(min(size, blocksize))
        if not data:
            break
        size -= len(data)
        fho.write(data)
    if size != 0:
        raise ZipError("Unexpected EOF")


def extract_meta(signed_apk: str) -> Iterator[Tuple[zipfile.ZipInfo, bytes]]:
    """
    Extract v1 signature metadata files from signed APK.

    Yields (ZipInfo, data) pairs.

    >>> from apksigcopier import extract_meta
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(extract_meta(apk))
    >>> [ x.filename for x, _ in meta ]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> for line in meta[0][1].splitlines()[:4]:
    ...     print(line.decode())
    Signature-Version: 1.0
    Created-By: 1.0 (Android)
    SHA-256-Digest-Manifest: hz7AxDJU9Namxoou/kc4Z2GVRS9anCGI+M52tbCsXT0=
    X-Android-APK-Signed: 2, 3
    >>> for line in meta[2][1].splitlines()[:2]:
    ...     print(line.decode())
    Manifest-Version: 1.0
    Created-By: 1.8.0_45-internal (Oracle Corporation)

    """
    with zipfile.ZipFile(signed_apk, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.filename):
                yield info, zf_sig.read(info.filename)


def extract_differences(signed_apk: str, extracted_meta: ZipInfoDataPairs) \
        -> Optional[Dict[str, Any]]:
    """
    Extract ZIP metadata differences from signed APK.

    >>> import apksigcopier as asc, pprint
    >>> apk = "test/apks/apks/debuggable-boolean.apk"
    >>> meta = tuple(asc.extract_meta(apk))
    >>> [ x.filename for x, _ in meta ]
    ['META-INF/CERT.SF', 'META-INF/CERT.RSA', 'META-INF/MANIFEST.MF']
    >>> diff = asc.extract_differences(apk, meta)
    >>> pprint.pprint(diff)
    {'files': {'META-INF/CERT.RSA': {'flag_bits': 2056},
               'META-INF/CERT.SF': {'flag_bits': 2056},
               'META-INF/MANIFEST.MF': {'flag_bits': 2056}}}

    >>> meta[2][0].extract_version = 42
    >>> try:
    ...     asc.extract_differences(apk, meta)
    ... except asc.ZipError as e:
    ...     print(e)
    Unsupported extract_version

    >>> asc.validate_differences(diff) is None
    True
    >>> diff["files"]["META-INF/OOPS"] = {}
    >>> asc.validate_differences(diff)
    ".files key 'META-INF/OOPS' is not a metadata file"
    >>> del diff["files"]["META-INF/OOPS"]
    >>> diff["files"]["META-INF/CERT.RSA"]["compresslevel"] = 42
    >>> asc.validate_differences(diff)
    ".files['META-INF/CERT.RSA'].compresslevel has an unexpected value"
    >>> diff["oops"] = 42
    >>> asc.validate_differences(diff)
    'contains unknown key(s)'

    """
    differences: Dict[str, Any] = {}
    files = {}
    for info, data in extracted_meta:
        diffs = {}
        for k in VALID_ZIP_META:
            if k != "compresslevel":
                v = getattr(info, k)
                if v != APKZipInfo._override[k]:
                    if v not in VALID_ZIP_META[k]:
                        raise ZipError(f"Unsupported {k}")
                    diffs[k] = v
        level = _get_compresslevel(signed_apk, info, data)
        if level != APKZipInfo.COMPRESSLEVEL:
            diffs["compresslevel"] = level
        if diffs:
            files[info.filename] = diffs
    if files:
        differences["files"] = files
    zfe_size = detect_zfe(signed_apk)
    if zfe_size:
        differences["zipflinger_virtual_entry"] = zfe_size
    return differences or None


def validate_differences(differences: Dict[str, Any]) -> Optional[str]:
    """
    Validate differences dict.

    Returns None if valid, error otherwise.
    """
    if set(differences) - {"files", "zipflinger_virtual_entry"}:
        return "contains unknown key(s)"
    if "zipflinger_virtual_entry" in differences:
        if type(differences["zipflinger_virtual_entry"]) is not int:
            return ".zipflinger_virtual_entry is not an int"
        if not (30 <= differences["zipflinger_virtual_entry"] <= 4096):
            return ".zipflinger_virtual_entry is < 30 or > 4096"
    if "files" in differences:
        if not isinstance(differences["files"], dict):
            return ".files is not a dict"
        for name, info in differences["files"].items():
            if not is_meta(name):
                return f".files key {name!r} is not a metadata file"
            if not isinstance(info, dict):
                return f".files[{name!r}] is not a dict"
            if set(info) - set(VALID_ZIP_META):
                return f".files[{name!r}] contains unknown key(s)"
            for k, v in info.items():
                if v not in VALID_ZIP_META[k]:
                    return f".files[{name!r}].{k} has an unexpected value"
    return None


def _get_compresslevel(apkfile: str, info: zipfile.ZipInfo, data: bytes) -> int:
    if info.compress_type != 8:
        raise ZipError("Unsupported compress_type")
    crc = _get_compressed_crc(apkfile, info)
    for level in VALID_ZIP_META["compresslevel"]:
        comp = zlib.compressobj(level, 8, -15)
        if zlib.crc32(comp.compress(data) + comp.flush()) == crc:
            return level
    raise ZipError("Unsupported compresslevel")


def _get_compressed_crc(apkfile: str, info: zipfile.ZipInfo) -> int:
    with open(apkfile, "rb") as fh:
        fh.seek(info.header_offset)
        hdr = fh.read(30)
        if hdr[:4] != b"\x50\x4b\x03\x04":
            raise ZipError("Expected local file header signature")
        n, m = struct.unpack("<HH", hdr[26:30])
        fh.seek(n + m, os.SEEK_CUR)
        return zlib.crc32(fh.read(info.compress_size))


def patch_meta(extracted_meta: ZipInfoDataPairs, output_apk: str,
               date_time: DateTime = DATETIMEZERO, *,
               differences: Optional[Dict[str, Any]] = None) -> None:
    """
    Add v1 signature metadata to APK (removes v2 sig block, if any).

    >>> import apksigcopier as asc
    >>> unsigned_apk = "test/apks/apks/golden-aligned-in.apk"
    >>> signed_apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(asc.extract_meta(signed_apk))
    >>> [ x.filename for x, _ in meta ]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> with zipfile.ZipFile(unsigned_apk, "r") as zf:
    ...     infos_in = zf.infolist()
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     asc.copy_apk(unsigned_apk, out)
    ...     asc.patch_meta(meta, out)
    ...     with zipfile.ZipFile(out, "r") as zf:
    ...         infos_out = zf.infolist()
    (2017, 5, 15, 11, 28, 40)
    >>> for i in infos_in:
    ...     print(i.filename)
    META-INF/
    META-INF/MANIFEST.MF
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> for i in infos_out:
    ...     print(i.filename)
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    META-INF/RSA-2048.SF
    META-INF/RSA-2048.RSA
    META-INF/MANIFEST.MF

    """
    with zipfile.ZipFile(output_apk, "r") as zf_out:
        for info in zf_out.infolist():
            if is_meta(info.filename):
                raise ZipError("Unexpected metadata")
    with zipfile.ZipFile(output_apk, "a") as zf_out:
        for info, data in extracted_meta:
            if differences and "files" in differences:
                more = differences["files"].get(info.filename, {}).copy()
            else:
                more = {}
            level = more.pop("compresslevel", APKZipInfo.COMPRESSLEVEL)
            zinfo = APKZipInfo(info, date_time=date_time, **more)
            zf_out.writestr(zinfo, data, compresslevel=level)


def extract_v2_sig(apkfile: str, expected: bool = True) -> Optional[Tuple[int, bytes]]:
    """
    Extract APK Signing Block and offset from APK.

    When successful, returns (sb_offset, sig_block); otherwise raises
    NoAPKSigningBlock when expected is True, else returns None.

    >>> import apksigcopier as asc
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> sb_offset, sig_block = asc.extract_v2_sig(apk)
    >>> sb_offset
    8192
    >>> len(sig_block)
    4096

    >>> apk = "test/apks/apks/golden-aligned-in.apk"
    >>> try:
    ...     asc.extract_v2_sig(apk)
    ... except asc.NoAPKSigningBlock as e:
    ...     print(e)
    No APK Signing Block

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


# FIXME: OSError for APKs < 1024 bytes [wontfix]
def zip_data(apkfile: str, count: int = 1024) -> ZipData:
    """
    Extract central directory, EOCD, and offsets from ZIP.

    Returns ZipData.

    >>> import apksigcopier
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> data = apksigcopier.zip_data(apk)
    >>> data.cd_offset, data.eocd_offset
    (12288, 12843)
    >>> len(data.cd_and_eocd)
    577

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
def patch_v2_sig(extracted_v2_sig: Tuple[int, bytes], output_apk: str) -> None:
    """
    Implant extracted v2/v3 signature into APK.

    >>> import apksigcopier as asc
    >>> unsigned_apk = "test/apks/apks/golden-aligned-in.apk"
    >>> signed_apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(asc.extract_meta(signed_apk))
    >>> v2_sig = asc.extract_v2_sig(signed_apk)
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     date_time = asc.copy_apk(unsigned_apk, out)
    ...     asc.patch_meta(meta, out, date_time=date_time)
    ...     asc.extract_v2_sig(out, expected=False) is None
    ...     asc.patch_v2_sig(v2_sig, out)
    ...     asc.extract_v2_sig(out) == v2_sig
    ...     with open(signed_apk, "rb") as a, open(out, "rb") as b:
    ...         a.read() == b.read()
    True
    True
    True

    """
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


def patch_apk(extracted_meta: ZipInfoDataPairs, extracted_v2_sig: Optional[Tuple[int, bytes]],
              unsigned_apk: str, output_apk: str, *,
              differences: Optional[Dict[str, Any]] = None,
              exclude: Optional[Callable[[str], bool]] = None) -> None:
    """Patch extracted_meta + extracted_v2_sig (if not None) onto unsigned_apk and save as output_apk."""
    if differences and "zipflinger_virtual_entry" in differences:
        zfe_size = differences["zipflinger_virtual_entry"]
    else:
        zfe_size = None
    date_time = copy_apk(unsigned_apk, output_apk, exclude=exclude, zfe_size=zfe_size)
    patch_meta(extracted_meta, output_apk, date_time=date_time, differences=differences)
    if extracted_v2_sig is not None:
        patch_v2_sig(extracted_v2_sig, output_apk)


# FIXME: support multiple signers?
def do_extract(signed_apk: str, output_dir: str, v1_only: NoAutoYesBoolNone = NO,
               *, ignore_differences: bool = False) -> None:
    """
    Extract signatures from signed_apk and save in output_dir.

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
    if not ignore_differences:
        differences = extract_differences(signed_apk, extracted_meta)
        if differences:
            with open(os.path.join(output_dir, "differences.json"), "w") as fh:
                json.dump(differences, fh, sort_keys=True, indent=2)
                fh.write("\n")


# FIXME: support multiple signers?
def do_patch(metadata_dir: str, unsigned_apk: str, output_apk: str,
             v1_only: NoAutoYesBoolNone = NO, *,
             exclude: Optional[Callable[[str], bool]] = None,
             ignore_differences: bool = False) -> None:
    """
    Patch signatures from metadata_dir onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = []
    differences = None
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
            differences_file = os.path.join(metadata_dir, "differences.json")
            if not ignore_differences and os.path.exists(differences_file):
                with open(differences_file, "r") as fh:
                    try:
                        differences = json.load(fh)
                    except json.JSONDecodeError as e:
                        raise APKSigCopierError(f"Invalid differences.json: {e}")   # pylint: disable=W0707
                    error = validate_differences(differences)
                    if error:
                        raise APKSigCopierError(f"Invalid differences.json: {error}")
    if not extracted_meta and extracted_v2_sig is None:
        raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              differences=differences, exclude=exclude)


def do_copy(signed_apk: str, unsigned_apk: str, output_apk: str,
            v1_only: NoAutoYesBoolNone = NO, *,
            exclude: Optional[Callable[[str], bool]] = None,
            ignore_differences: bool = False) -> None:
    """
    Copy signatures from signed_apk onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = tuple(extract_meta(signed_apk))
    differences = None
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        extracted_v2_sig = extract_v2_sig(signed_apk, expected=v1_only == NO)
        if extracted_v2_sig is not None and not ignore_differences:
            differences = extract_differences(signed_apk, extracted_meta)
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              differences=differences, exclude=exclude)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
