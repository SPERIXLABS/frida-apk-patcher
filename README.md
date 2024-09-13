
# APK Patcher for Frida Instrumentation

This tool allows you to patch APK files for Frida instrumentation using the Frida gadget. It injects the required libraries and smali code into the APK, re-signs it, and ensures the APK is ready to use with Frida for reverse engineering or penetration testing.

---

## Features

- Disassembles APK files using `apktool`
- Adds `INTERNET` permission and custom `network_security_config.xml` if not already present
- Injects Frida gadget libraries into the APK
- Modifies the APK's smali code to load the Frida gadget
- Rebuilds, aligns, and signs the APK for use
- Compatible with Android versions that support APK Signature Schemes v1 and v2

## Prerequisites

Before using this tool, ensure the following tools are installed on your system:

- `aapt` (Android Asset Packaging Tool)
- `apktool`
- `zipalign`
- `apksigner`
- Python 3.x
- Java Development Kit (JDK) for APK signing

## Usage

### Step 1: Clone the Repository

```bash
git clone https://github.com/sperixlabs/frida-apk-patcher.git
cd frida-apk-patcher
```

### Step 2: Prepare Your APK

Place the APK you want to patch in a known directory. Note the absolute path to the APK, as it will be needed during execution.

### Step 3: Download Frida Gadget

Run `getlibs.sh` to fetch the latest Frida Gadgets

```bash
bash getlibs.sh
```

### Step 4: Run the Tool

Run the script with the path to the APK you want to patch. Here's the command:

```bash
python apk_builder.py --apk /path/to/your.apk
```

### Example:

```bash
python apk_builder.py --apk /home/user/downloads/sample.apk
```

### Step 5: Patched APK Output

After the tool finishes running, it will output the patched APK file as `your-apk-appmon.apk` in the same directory where the original APK was located.

### Options:

- `--apk`: Absolute path to the APK you want to patch.

### Output Files:

- The patched APK file will be created in the current working directory as `app_name-appmon.apk`.

## Troubleshooting

- **Signing Errors**: Ensure you have the correct Java Development Kit (JDK) installed and set up. The signing process uses `apksigner`, which requires the keystore and password (`appmon.keystore` and `pass:appmon` in this case) to sign the APK.

- **Zipalign Issues**: Ensure `zipalign` is correctly installed and available in your PATH environment variable. If you're using Android SDK, this tool is located in the `build-tools` directory.


## Contributing

Feel free to open issues or submit pull requests if you find any bugs or want to contribute to improving this tool. Your contributions are welcome!

---

## Authors

- [Nishant Das Patnaik](https://github.com/dpnishant)
- [Jay Lux Ferro](https://github.com/jayluxferro)
