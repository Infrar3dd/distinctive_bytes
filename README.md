# distinctive_bytes

INT-9 | Script that computes byte arrays covering files in group G1 that are absent from files in group G2

### Usage

```
python3 distinctive_bytes.py --help
usage: distinctive_bytes.py [-h] --g1 FILE [FILE ...] [--g2 [FILE ...]] [--min-len N]
                            [--max-len N] [--top K] [--step S] [--out FILE] [--yara FILE]
                            [--yara-name YARA_NAME] [--no-unzip] [--quiet]

Find byte sequences in ALL G1 files but ABSENT from all G2 files.

options:
  -h, --help            show this help message and exit
  --g1 FILE [FILE ...]
  --g2 [FILE ...]
  --min-len N
  --max-len N
  --top K
  --step S              Sliding-window step (default 4; 1 for exhaustive but slow)
  --out FILE            JSON output
  --yara FILE           YARA rule output
  --yara-name YARA_NAME
  --no-unzip            Treat APK/ZIP as raw bytes, don't extract inner files
  --quiet
```

### Example

There's also out.json in this repo

```
$ python3 distinctive_bytes.py -g2 1ae3e8213b07e1d53eca54a1901e2dc6dc9e27a3ca10377a63e6adec2fe15426.apk 2152b98a832ce3e442b486ceeaa8e41a8a99657168 986757913e2d916c7b1c21.apk -g1 7add757c3f09d52863fcc07948491ad967a7f0a9a51bbabb8567c26b8bfecfda.apk 1f333d910158316c6211f7b24d118aadca778abb3964f3a4b7d3914a49278b7d.apk 1e472dbf492bdd.apk --out out.json --step 4 --max-len 10
[*] G1=2, G2=2, lengths 8-10, step=4, unzip=True
G1          21,238,774  B  7add757c3f09d52863fcc07948491ad967a7f0a9a51bbabb8567c26b8bfecfda.apk
G1           9,513,281  B  1f333d910158316c6211f7b24d118aadca778abb3964f3a4b7d3914a49278b7d.apk
G2          21,238,883  B  1ae3e8213b07e1d53eca54a1901e2dc6dc9e27a3ca10377a63e6adec2fe15426.apk
G2             214,685  B  2152b98a832ce3e442b486ceeaa8e41a8a99657168986757913e2d916c7b1c21.apk
[len= 8]  37,673  G1-common -> 46  survive G2
[len= 9]  29,881  G1-common -> 41  survive G2
[len=10]  25,535  G1-common -> 42  survive G2
[*] Deduplicating 129 sequences... 59 maximal remain

--------------------------------------------------------------------------------
TOP 20 DISTINCTIVE SEQUENCES
--------------------------------------------------------------------------------
 1. ( 10B)  6375726974792f636572                [curity/cer]
 2. ( 10B)  000b746f436861724172                [tOCharAr]
 3. ( 10B)  6c656373746976654f65                [lectiveOpe]
 4. ( 10B)  6b6574466176616e744c6f                [ketFactory]
 5. ( 10B)  1e4c6a6176612f6e6574                [.Ljava/net]
 6. ( 10B)  7574696c2f7a69702f5a                [util/zip/Z]
 7. ( 10B)  65744162736f6c757465                [etAbsolute]
 8. ( 10B)  2f73732e2f5472757374                [/ss/.Trust]
 9. ( 10B)  6976654f706572617469                [iveOperati]
10. ( 10B)  7065726d697373696f6e45                [permissionE]
11. ( 10B)  727441786d6c4368617261                [rtAxmlChara]
12. ( 10B)  6c65467472616e73666f72                [leTransform]
13. ( 10B)  000867657374726f6d2f                [..gestrom/]
14. ( 10B)  4c536f636b6574466163                [LSocketFac]
15. ( 10B)  2f5265666c656374696f6e                [/Reflection]
16. ( 10B)  676574536f636b65744674                [getSocketFt]
17. ( 10B)  5835303934357274696e67                [X509Certif]
18. ( 10B)  53534c536f636b65744674                [SSLSocketFt]
19. ( 10B)  4e6f74466f756e64457863                [NotFoundExc]
20. ( 10B)  7874656e73696f6e732d                [xtensions-]

[*] Full results -> out.json
[*] Total: 59 distinctive sequences
```