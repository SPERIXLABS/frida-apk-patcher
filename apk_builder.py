#!/usr/bin/python3

###
# Copyright (c) 2016 Nishant Das Patnaik.
# Copyright (c) 2024 Jay Lux Ferro
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

import argparse
import codecs
import os
import shutil
import subprocess
import sys
import traceback
from xml.etree import ElementTree
import re


def find_smali_folders(root_folder: str) -> list:
    # Regular expression to match folder names like smali, smali_classes2, smali_classes3, etc.
    smali_pattern = re.compile(r'^smali(_classes\d+)?$')

    smali_folders = []

    # Walk through the directory tree
    for root, dirs, files in os.walk(root_folder):
        for dir_name in dirs:
            if smali_pattern.match(dir_name):
                smali_folders.append(os.path.join(root, dir_name))

    return smali_folders


parser = argparse.ArgumentParser()
parser.add_argument('--apk', action='store', dest='apk_path', default='', help='''(absolute) path to APK''')
parser.add_argument('-v', action='version', version='APK Builder v0.1')

if len(sys.argv) < 3:
    parser.print_help()
    sys.exit(1)

results = parser.parse_args()
apk_path = results.apk_path
new_apk_path = ""
aligned_apk_path = ""
renamed_apk_path = ""

if not os.path.isfile(apk_path):
    print("[E] File doesn't exist: %s\n[*] Quitting!" % apk_path)
    sys.exit(1)

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

WORK_DIR = "/tmp/appmon_apk"
LIB_FILE_PATH = "lib.zip"

lib_dir = ""
marker = 0
method_start = 0
method_end = 0
constructor_start = 0
constructor_end = 0
prologue_start = 0
header_range = list(range(0, 0))
footer_range = list(range(0, 0))
header_block = ""
footer_block = ""

try:
    if os.path.isdir(WORK_DIR):
        print("[I] Preparing work directory...")
        shutil.rmtree(WORK_DIR)
    os.makedirs(WORK_DIR)

    print("[I] Expanding APK...")
    apk_dump = subprocess.check_output(["aapt", "dump", "badging", apk_path]).decode()
    apk_permissions = subprocess.check_output(["aapt", "dump", "permissions", apk_path]).decode()
    package_name = apk_dump.split("package: name=")[1].split(" ")[0].strip("'\"\n\t ")
    manifest_file_path = os.path.join(WORK_DIR, package_name, "AndroidManifest.xml")
    try:
        launchable_activity = apk_dump.split("launchable-activity: name=")[1].split(" ")[0].strip("'\"\n\t ")
    except IndexError:
        print("No launchable activity found")
        sys.exit(1)

    new_apk_path = WORK_DIR + "/" + package_name + ".apk"
    subprocess.call(["cp", apk_path, new_apk_path])
    subprocess.call(["apktool", "-q", "-f", "d", new_apk_path])
    subprocess.call(["mv", package_name, WORK_DIR])

    # support for multi-dex
    smali_class_folders = find_smali_folders(os.path.join(WORK_DIR, package_name))
    launchable_activity_path = None
    for smali_class_folder in smali_class_folders:
        launchable_activity_smali_path = os.path.join(smali_class_folder,
                                                      launchable_activity.replace(".", "/") + ".smali")
        if os.path.isfile(launchable_activity_smali_path):
            launchable_activity_path = launchable_activity_smali_path

    if launchable_activity_path is None:
        print("No launchable activity found")
        sys.exit(1)

    if "uses-permission: name='android.permission.INTERNET'" not in apk_permissions:
        print("[I] APK needs INTERNET permission")
        with codecs.open(manifest_file_path, 'r', 'utf-8') as f:
            manifest_file_contents = f.readlines()

        for line_num in range(0, len(manifest_file_contents)):
            if "android.permission.INTERNET" in manifest_file_contents[line_num]:
                manifest_file_contents.insert(line_num,
                                              "    <uses-permission android:name=\"android.permission.INTERNET\"/>\n")
                with codecs.open(manifest_file_path, 'w', 'utf-8') as f:
                    manifest_file_contents = "".join(manifest_file_contents)
                    f.write(manifest_file_contents)
                break

    # extractNativeLibs, networkSecurityConfig
    res_path = os.path.join(WORK_DIR + "/" + package_name, "res/xml")
    res_path = os.path.abspath(res_path)
    if not os.path.exists(res_path):
        os.makedirs(res_path)
    print("[I] Adding network file")

    file = "network_security_config.xml"
    with open(file, "r") as network_file:
        with open(os.path.join(res_path, file), "w+") as new_network_file:
            new_network_file.write(network_file.read())

    if os.path.isfile(manifest_file_path):
        ElementTree.register_namespace("android", "http://schemas.android.com/apk/res/android")

        tree = ElementTree.parse(manifest_file_path)
        if tree is not None:
            tree_root = tree.getroot()
            if tree_root is not None:
                application = tree_root.find("application")
                application.set("{http://schemas.android.com/apk/res/android}networkSecurityConfig",
                                "@xml/network_security_config")
                application.set("{http://schemas.android.com/apk/res/android}extractNativeLibs",
                                "true")

                with open(manifest_file_path, "wb") as xml_file:
                    xml_file.write('<?xml version="1.0" encoding="utf-8" standalone="no"?>'.encode())
                    xml_file.write(ElementTree.tostring(tree_root))

    print("[I] Searching .smali")
    with codecs.open(launchable_activity_path, 'r', 'utf-8') as f:
        file_contents = f.readlines()

    for line in range(0, len(file_contents)):
        if "# direct methods" in file_contents[line]:
            method_start = line
        if "# virtual methods" in file_contents[line]:
            method_end = line

    marker = method_start + 1

    if (method_end - method_start) > 1:
        for cursor in range(marker, method_end):
            if ".method static constructor <clinit>()V" in file_contents[cursor]:
                constructor_start = cursor
                marker = constructor_start - 1
                break
        for cursor in range(marker, method_end):
            if ".end method" in file_contents[cursor]:
                constructor_end = cursor - 1
                break
        for cursor in range(marker, constructor_end):
            if ".locals" in file_contents[cursor] or ".prologue" in file_contents[cursor]:
                prologue_start = cursor
                marker = cursor + 1

    header_range = list(range(0, marker))
    footer_range = list(range(marker, len(file_contents)))

    for line_num in header_range:
        header_block += file_contents[line_num]
    for line_num in footer_range:
        footer_block += file_contents[line_num]

    if prologue_start > 1:
        renegerated_smali = header_block + SMALI_PROLOGUE + footer_block
    else:
        renegerated_smali = header_block + SMALI_DIRECT_METHODS + footer_block

    print("[I] Patching .smali")
    with codecs.open(launchable_activity_path, 'w', 'utf-8') as f:
        f.write(renegerated_smali)

    print("[I] Injecting libs")
    lib_dir = os.path.join(WORK_DIR, package_name, "lib")
    if not os.path.isdir(lib_dir):
        os.makedirs(lib_dir)

    unzip_output = subprocess.check_output(["unzip", LIB_FILE_PATH, "-d", lib_dir])

    print("[I] Building APK")
    shutil.rmtree(os.path.join(WORK_DIR, package_name, "original/META-INF"))
    build_apk_output = subprocess.check_output(["apktool", "build", os.path.join(WORK_DIR, package_name)])

    new_apk_path = "%s/%s.apk" % (os.path.join(WORK_DIR, package_name, "dist"), package_name)
    aligned_apk_path = "%s/%s-zipaligned.apk" % (os.path.join(WORK_DIR, package_name, "dist"), package_name)
    signed_apk_path = "%s/%s-zipaligned-signed.apk" % (os.path.join(WORK_DIR, package_name, "dist"), package_name)
    renamed_apk_path = "%s/%s.apk" % (
        os.path.join(WORK_DIR, package_name, "dist"), os.path.basename(apk_path).split(".apk")[0] + "-appmon")
    appmon_apk_path = os.path.join(os.getcwd(), os.path.basename(apk_path).split(".apk")[0] + "-appmon.apk")

    print("[I] Aligning APK")
    subprocess.check_output(["zipalign", "-v", "-p", "-f", "4", new_apk_path, aligned_apk_path])

    align_verify = subprocess.check_output(["zipalign", "-v", "-c", "4", aligned_apk_path]).decode()
    align_verify.strip(" \r\n\t")
    if "Verification succesful" not in align_verify:
        print("[E] alignment verification failed")
    else:
        print("[I] APK alignment verified")

    #
    print("[I] Signing APK")
    sign_status = subprocess.check_output(
        ["apksigner", "sign", "--verbose", "--ks", "appmon.keystore", "--ks-pass", "pass:appmon", "--out",
         signed_apk_path, aligned_apk_path]).decode()

    if "Signed" not in sign_status:
        print("[E] APK signing error %s" % sign_status)

    sign_verify = subprocess.check_output(["apksigner", "verify", "--verbose", signed_apk_path]).decode()

    if "Verified using v1 scheme (JAR signing): true" not in sign_verify and "Verified using v2 scheme (APK Signature Scheme v2): true" not in sign_verify:
        print(sign_verify)
    else:
        print("[I] APK signature verified")

    print("[I] Housekeeping")
    subprocess.call(["mv", signed_apk_path, renamed_apk_path])
    subprocess.call(["mv", renamed_apk_path, os.getcwd()])
    subprocess.call(["rm", new_apk_path, aligned_apk_path])

    if os.path.isfile(appmon_apk_path):
        print("[I] Ready: %s" % appmon_apk_path)

except Exception as e:
    traceback.print_exc()
    sys.exit(1)
