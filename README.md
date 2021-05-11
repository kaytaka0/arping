# Arping

pythonによるArpingの実装をおこなう。

## 実行方法
```bash
$ sudo python3 arping.py [-h] [--interface INTERFACE] tagrgetip
// 例
$ sudo python3 arping.py 192.0.1.12
```

## ARPとは
Address Resolution Protocolは、IPアドレスとMACアドレスを結びつけるプロトコル。
IPアドレスに対応するホスト、ルーターのMACアドレスを取得するために用いられる。

## 動作検証環境
Linux仮想環境にて動作確認を行った。

- ホストマシン: M1 Mac ARM
- 仮想環境ソフトウェア: UTM
- 仮想環境OS: ubuntu 20.04.2 server
```
$ uname -a
Linux linuxserver 5.4.0-72-generic #80-Ubuntu SMP Mon Apr 12 17:32:12 UTC 2021 aarch64 aarch64 aarch64 GNU/Linux
```

## メモ

- `Mac OS X`の`python`に`socket.AF_PACKET`が存在しない。(`AF_PACKET`はethernetパケットから作成する、低レベルソケットを取得するプロトコルファミリ引数)
似たようなものに`BPF`というものがあるらしい。[stackoverflow](https://stackoverflow.com/questions/7284853/af-packet-equivalent-under-mac-os-x-darwin)
> AF_PACKET is a low-level interface directly to network devices.  

- 同じコードを実行しても異なるARP応答が帰ってきた。
```bash
linuxbeginner@linuxserver:~$ sudo python3 arping.py 192.0.0.23
ARP sent....
b'\x00\x00\x00\x00\x00\x00\xee\xe2\x1d\x9c\xb1\xcb\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xee\xe2\x1d\x9c\xb1\xcb\x7f\x00\x01\x01\x00\x00\x00\x00\x00\x00\n\x00\x02\x03'
==================================================
b"RU\n\x00\x02\x02\xee\xe2\x1d\x9c\xb1\xcb\x08\x00E\x10\x01<\xc0\xfc@\x00@\x06`\x9f\n\x00\x02\x0f\n\x00\x02\x02\x00..........."
```

```bash
linuxbeginner@linuxserver:~$ sudo python3 arping.py 192.0.0.23
ARP sent....
b'\x00\x00\x00\x00\x00\x00\xee\xe2\x1d\x9c\xb1\xcb\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xee\xe2\x1d\x9c\xb1\xcb\x7f\x00\x01\x01\x00\x00\x00\x00\x00\x00\n\x00\x02\x03'
==================================================
b'\xee\xe2\x1d\x9c\xb1\xcbRU\n\x00\x02\x03\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02RU\n\x00\x02\x03\n\x00\x02\x03\xee\xe2\x1d\x9c\xb1\xcb\x7f..........'
```

- IPパケットやARPパケットが受信されたため、受信データの宛先MACアドレスと、プロトコルタイプの確認が必要
- Linuxの`arping`コマンドはインタフェース名を入力しなくても実行できるが、これはインタフェースを推測しているようだった。今回作成したコマンドでも推測できない場合にエラーメッセージを出力するようにした。

## 参考

- マスタリングTCP/IP 入門編　第5版
- [PythonでARPを使ったネットワークプログラミング　ARPスプーフィングを試す](https://euniclus.com/article/python-arp-spoofing/)
- [RFC826 日本語訳](http://srgia.com/docs/rfc826j.html)
- [Arping Command on Linux Explained](https://devconnected.com/arping-command-on-linux-explained/)
