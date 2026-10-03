
# APK Patcher for Frida Instrumentation

This tool allows you to patch APK files for Frida instrumentation using the Frida gadget. It injects the required libraries and smali code into the APK, re-signs it, and ensures the APK is ready to use with Frida for reverse engineering or penetration testing.

It works in two stages:

1. **Zip surgery (default, robust).** The manifest is patched as binary AXML directly inside the zip — `debuggable`, `usesCleartextTraffic` and a compiled debug `network_security_config` are added without apktool decode/rebuild. The dex and resources are copied byte-for-byte, so apps that apktool cannot round-trip (HDO Box 4.4.6 and friends) still come out working. Ported from APKProxyHelper.py, plus fixes: attributes are re-sorted by resource id (the framework's merge-walk silently drops out-of-order attrs), styled string pools keep their style-offset table, and `res/xml` payloads are compiled AXML, never text.
2. **Gadget stage.** apktool decode, smali patch (the loader is anchored to the class's `<clinit>` — never to the first direct method, which in r8 apps is a synthetic `$r8$lambda$` whose registers are live), lib.zip injection, rebuild, then the same zip surgery + align + sign. If the apktool round-trip fails on an app, the tool warns and falls back to stage 1.

---

## Features

- Adds `INTERNET` permission (when missing), `debuggable`, `usesCleartextTraffic="true"` and a debug `network_security_config.xml`
- Zip-surgery patching that never decodes the APK (default safe path)
- Optional Frida-gadget injection via apktool with automatic fallback
- Rebuilds, aligns, and signs the APK for use
- Compatible with Android versions that support APK Signature Schemes v1, v2 and v3

## Prerequisites

Before using this tool, ensure the following tools are installed on your system:

- `aapt`/`aapt2` (Android Asset Packaging Tool)
- `apktool`
- `zipalign`
- `apksigner`
- Python 3.x
- Java Development Kit (JDK) for APK signing

## Usage

### Step 1: Prepare Your APK

Place the APK you want to patch in a known directory, and work on a COPY — the original is never modified.

### Step 2: Download Frida Gadget (only needed for the gadget stage)

Run `getlibs.sh` to fetch Frida Gadgets. Pass the version to match your AppMon/frida client:

```bash
bash getlibs.sh 16.1.3
```

Version alignment matters: AppMon's scripts use the frida-js bridges bundled in the frida 16.x client runtime (frida 17 removed them — the client is pinned to `frida==16.x` in appmon's requirements.txt), so keep the gadget on the same 16.x line. The bench emulator's frida-server may be newer; that only affects server-side attach, not the embedded gadget.

### Step 3: Run the Tool

```bash
python apk_builder.py --apk /path/to/your.apk [--manifest-only] [--out /path/to/out.apk]
```

- `--apk`: path to the APK to patch.
- `--manifest-only`: skip the frida-gadget injection entirely (no apktool round-trip); just the manifest/NSC patch + align + sign.
- `--out`: output path (default `<apk>-appmon.apk` next to the input).
- `-v`: version banner.

### Output Files:

- The patched APK is aligned and signed with the bundled `appmon.keystore` (pass:appmon).


## Using the patched app
- Gadget builds (over USB):

```
frida -U Gadget -l [frida_script]
```

- Specific Device

```
frida Gadget -l [frida_script] -D [device_name]
```

## Troubleshooting

- **Signing Errors**: Ensure you have the correct Java Development Kit (JDK) installed and set up. The signing process uses `apksigner`, which requires the keystore and password (`appmon.keystore` and `pass:appmon` in this case) to sign the APK.

- **Zipalign Issues**: Ensure `zipalign` is correctly installed and available in your PATH environment variable. If you're using Android SDK, this tool is located in the `build-tools` directory.


## Contributing

Feel free to open issues or submit pull requests if you find any bugs or want to contribute to improving this tool. Your contributions are welcome!

---

## Authors

- [Nishant Das Patnaik](https://github.com/dpnishant)
- [Jay Lux Ferro](https://github.com/jayluxferro)
