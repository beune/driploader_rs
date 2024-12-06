# driploader_rs

This is my rust port of xuanxuan0's [DripLoader](https://github.com/xuanxuan0/DripLoader). It is a shellcode injection technique where the shellcode is split up in parts of 4096 bytes. It is then allocated, written and reprotected part by part, with sleep statements in between in order to evade detection.

## Usage

```cmd
driploader.exe --shellcode <SHELLCODE> --milliseconds <MILLISECONDS>
```

* `shellcode`: path to shellcode file
* `milliseconds` number of milliseconds to sleep between operations

## Disclaimer

This project is intended solely for educational and research purposes. It is provided to help developers and security professionals understand shellcode execution techniques in a controlled and ethical manner.

Misuse Warning:
Using this tool for unauthorized or malicious activities is strictly prohibited and may violate local, state, or international laws. The author is not responsible for any misuse of this code.

Always obtain proper authorization before deploying this tool in any environment. By using this project, you agree to use it responsibly and ethically.
