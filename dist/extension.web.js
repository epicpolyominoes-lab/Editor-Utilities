(function () {

var __mods = {}, __cache = {};
var __FILES = {"templates/c.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n#define MAGIC 0x@@MAGIC@@u\n\nstatic const uint8_t KEY[] = { @@KEYLIST@@ };\n#define KEY_LEN (sizeof(KEY) / sizeof(KEY[0]))\n\nstatic uint32_t fnv1a(const uint8_t *data, size_t len) {\n    uint32_t h = 0x811C9DC5u;\n    for (size_t i = 0; i < len; i++) {\n        h ^= data[i];\n        h *= 0x01000193u;\n    }\n    return h;\n}\n\nstatic void xor_stream(const uint8_t *in, uint8_t *out, size_t len) {\n    for (size_t i = 0; i < len; i++) {\n        out[i] = in[i] ^ KEY[i % KEY_LEN] ^ (uint8_t)(i & 0xFF);\n    }\n}\n\nstatic void hexdump(const uint8_t *data, size_t len) {\n    for (size_t off = 0; off < len; off += 16) {\n        printf(\"%08zx  \", off);\n        for (size_t i = 0; i < 16; i++) {\n            if (off + i < len) printf(\"%02x \", data[off + i]);\n            else printf(\"   \");\n        }\n        printf(\" |\");\n        for (size_t i = 0; i < 16 && off + i < len; i++) {\n            uint8_t c = data[off + i];\n            putchar(c >= 32 && c < 127 ? c : '.');\n        }\n        printf(\"|\\n\");\n    }\n}\n\nstatic int @@SNAKE@@_seal(const char *msg, uint8_t **blob, size_t *blob_len) {\n    size_t n = strlen(msg);\n    uint8_t *buf = malloc(8 + n);\n    if (!buf) return -1;\n    uint32_t digest = fnv1a((const uint8_t *)msg, n);\n    uint32_t magic = MAGIC;\n    memcpy(buf, &magic, 4);\n    memcpy(buf + 4, &digest, 4);\n    xor_stream((const uint8_t *)msg, buf + 8, n);\n    *blob = buf;\n    *blob_len = 8 + n;\n    return 0;\n}\n\nstatic int @@SNAKE@@_unseal(const uint8_t *blob, size_t blob_len, char *out, size_t out_len) {\n    uint32_t magic, digest;\n    if (blob_len < 8 || blob_len - 8 >= out_len) return -1;\n    memcpy(&magic, blob, 4);\n    memcpy(&digest, blob + 4, 4);\n    if (magic != MAGIC) return -2;\n    xor_stream(blob + 8, (uint8_t *)out, blob_len - 8);\n    out[blob_len - 8] = '\\0';\n    if (fnv1a((const uint8_t *)out, blob_len - 8) != digest) return -3;\n    return 0;\n}\n\nint main(int argc, char **argv) {\n    const char *msg = argc > 1 ? argv[1] : \"hello from @@SNAKE@@\";\n    uint8_t *blob = NULL;\n    size_t blob_len = 0;\n    char plain[256];\n\n    printf(\"starting @@SNAKE@@\\n\");\n    if (@@SNAKE@@_seal(msg, &blob, &blob_len) != 0) return 1;\n    hexdump(blob, blob_len);\n    printf(\"[+] sealed %zu bytes, digest %08x\\n\", blob_len, fnv1a(blob, blob_len));\n    if (@@SNAKE@@_unseal(blob, blob_len, plain, sizeof(plain)) != 0) {\n        fprintf(stderr, \"[!] integrity check failed\\n\");\n        free(blob);\n        return 2;\n    }\n    printf(\"[+] opened: %s\\n\", plain);\n    free(blob);\n    return 0;\n}\n","templates/cpp.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\n#include <cstdint>\n#include <cstdio>\n#include <iostream>\n#include <stdexcept>\n#include <string>\n#include <vector>\n\nnamespace {\n\nconstexpr std::uint32_t kMagic = 0x@@MAGIC@@u;\nconst std::vector<std::uint8_t> kKey = { @@KEYLIST@@ };\n\nstd::uint32_t fnv1a(const std::vector<std::uint8_t>& data) {\n    std::uint32_t h = 0x811C9DC5u;\n    for (auto b : data) {\n        h ^= b;\n        h *= 0x01000193u;\n    }\n    return h;\n}\n\nstd::vector<std::uint8_t> xorStream(const std::vector<std::uint8_t>& in) {\n    std::vector<std::uint8_t> out(in.size());\n    for (std::size_t i = 0; i < in.size(); ++i) {\n        out[i] = static_cast<std::uint8_t>(in[i] ^ kKey[i % kKey.size()] ^ (i & 0xFF));\n    }\n    return out;\n}\n\nvoid hexdump(const std::vector<std::uint8_t>& data) {\n    for (std::size_t off = 0; off < data.size(); off += 16) {\n        std::printf(\"%08zx  \", off);\n        for (std::size_t i = 0; i < 16; ++i) {\n            if (off + i < data.size()) std::printf(\"%02x \", data[off + i]);\n            else std::printf(\"   \");\n        }\n        std::printf(\" |\");\n        for (std::size_t i = 0; i < 16 && off + i < data.size(); ++i) {\n            int c = data[off + i];\n            std::putchar(c >= 32 && c < 127 ? c : '.');\n        }\n        std::printf(\"|\\n\");\n    }\n}\n\n}  // namespace\n\nclass @@PASCAL@@ {\npublic:\n    std::vector<std::uint8_t> seal(const std::string& message) {\n        std::vector<std::uint8_t> body(message.begin(), message.end());\n        std::vector<std::uint8_t> blob;\n        const std::uint32_t digest = fnv1a(body);\n        for (int shift = 24; shift >= 0; shift -= 8) blob.push_back((kMagic >> shift) & 0xFF);\n        for (int shift = 24; shift >= 0; shift -= 8) blob.push_back((digest >> shift) & 0xFF);\n        for (auto b : xorStream(body)) blob.push_back(b);\n        ++sealed_;\n        return blob;\n    }\n\n    std::string unseal(const std::vector<std::uint8_t>& blob) const {\n        if (blob.size() < 8) throw std::runtime_error(\"short blob\");\n        std::uint32_t magic = 0, digest = 0;\n        for (int i = 0; i < 4; ++i) magic = (magic << 8) | blob[i];\n        for (int i = 4; i < 8; ++i) digest = (digest << 8) | blob[i];\n        if (magic != kMagic) throw std::runtime_error(\"bad magic\");\n        std::vector<std::uint8_t> body = xorStream(std::vector<std::uint8_t>(blob.begin() + 8, blob.end()));\n        if (fnv1a(body) != digest) throw std::runtime_error(\"integrity check failed\");\n        return std::string(body.begin(), body.end());\n    }\n\n    int sealed() const { return sealed_; }\n\nprivate:\n    int sealed_ = 0;\n};\n\nint main(int argc, char** argv) {\n    @@PASCAL@@ vault;\n    const std::string message = argc > 1 ? argv[1] : \"hello from @@SNAKE@@\";\n    std::cout << \"starting @@SNAKE@@\" << std::endl;\n    const auto blob = vault.seal(message);\n    hexdump(blob);\n    std::printf(\"[+] sealed %zu bytes, digest %08x\\n\", blob.size(), fnv1a(blob));\n    std::cout << \"[+] opened: \" << vault.unseal(blob) << std::endl;\n    return 0;\n}\n","templates/cs.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\nusing System;\nusing System.Buffers.Binary;\nusing System.Linq;\nusing System.Text;\n\ninternal sealed class @@PASCAL@@\n{\n    private const uint Magic = 0x@@MAGIC@@u;\n    private static readonly byte[] Key = { @@KEYLIST@@ };\n\n    public int Sealed { get; private set; }\n\n    internal static uint Fnv1a(byte[] data)\n    {\n        uint h = 0x811C9DC5u;\n        foreach (var b in data)\n        {\n            h ^= b;\n            h *= 0x01000193u;\n        }\n        return h;\n    }\n\n    internal static byte[] XorStream(byte[] input)\n    {\n        var output = new byte[input.Length];\n        for (var i = 0; i < input.Length; i++)\n        {\n            output[i] = (byte)(input[i] ^ Key[i % Key.Length] ^ (i & 0xFF));\n        }\n        return output;\n    }\n\n    internal static string Hexdump(byte[] data)\n    {\n        var sb = new StringBuilder();\n        for (var off = 0; off < data.Length; off += 16)\n        {\n            var chunk = data.Skip(off).Take(16).ToArray();\n            var hex = string.Join(\" \", chunk.Select(b => b.ToString(\"x2\")));\n            var txt = new string(chunk.Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());\n            sb.AppendLine(off.ToString(\"x8\") + \"  \" + hex.PadRight(48) + \" |\" + txt + \"|\");\n        }\n        return sb.ToString();\n    }\n\n    public byte[] Seal(string message)\n    {\n        var body = Encoding.UTF8.GetBytes(message);\n        var blob = new byte[8 + body.Length];\n        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(0, 4), Magic);\n        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(4, 4), Fnv1a(body));\n        XorStream(body).CopyTo(blob, 8);\n        Sealed++;\n        return blob;\n    }\n\n    public string Unseal(byte[] blob)\n    {\n        if (BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(0, 4)) != Magic)\n            throw new InvalidOperationException(\"bad magic\");\n        var body = XorStream(blob.Skip(8).ToArray());\n        if (Fnv1a(body) != BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(4, 4)))\n            throw new InvalidOperationException(\"integrity check failed\");\n        return Encoding.UTF8.GetString(body);\n    }\n}\n\ninternal static class Program\n{\n    private static int Main(string[] args)\n    {\n        var vault = new @@PASCAL@@();\n        var message = args.Length > 0 ? string.Join(\" \", args) : \"hello from @@SNAKE@@\";\n        Console.WriteLine(\"starting @@SNAKE@@\");\n        var blob = vault.Seal(message);\n        Console.Write(@@PASCAL@@.Hexdump(blob));\n        Console.WriteLine(\"[+] sealed \" + blob.Length + \" bytes, digest \" + @@PASCAL@@.Fnv1a(blob).ToString(\"x8\"));\n        Console.WriteLine(\"[+] opened: \" + vault.Unseal(blob));\n        return 0;\n    }\n}\n","templates/generic.tpl":"@@C@@ ============================================================\n@@C@@  @@FILE@@\n@@C@@  @@PASCAL@@ module\n@@C@@  created @@DATE@@\n@@C@@ ============================================================\n@@C@@\n@@C@@ Overview\n@@C@@   Reads records from the configured source, validates each one,\n@@C@@   and hands the clean results to the next stage.\n@@C@@\n@@C@@ Configuration\n@@C@@   source    @@HOST@@:@@PORT@@\n@@C@@   workers   @@KEYLEN@@\n@@C@@   timeout   30s\n@@C@@\n@@C@@ Pipeline\n@@C@@   1. read     fetch the next batch from the source\n@@C@@   2. validate reject malformed records, count them\n@@C@@   3. transform normalise fields and apply defaults\n@@C@@   4. emit     write @@PASCAL@@ records to the output queue\n@@C@@\n@@C@@ TODO: retry transient failures with backoff\n@@C@@ TODO: expose metrics for @@CAMEL@@\n@@C@@ TODO: add tests for the validation rules\n","templates/go.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\npackage main\n\nimport (\n    \"encoding/binary\"\n    \"errors\"\n    \"fmt\"\n    \"os\"\n    \"strings\"\n)\n\nconst magic uint32 = 0x@@MAGIC@@\n\nvar key = []byte{@@KEYLIST@@}\n\nfunc fnv1a(data []byte) uint32 {\n    h := uint32(0x811c9dc5)\n    for _, b := range data {\n        h ^= uint32(b)\n        h *= 0x01000193\n    }\n    return h\n}\n\nfunc xorStream(in []byte) []byte {\n    out := make([]byte, len(in))\n    for i, b := range in {\n        out[i] = b ^ key[i%len(key)] ^ byte(i&0xff)\n    }\n    return out\n}\n\nfunc hexdump(data []byte) string {\n    var sb strings.Builder\n    for off := 0; off < len(data); off += 16 {\n        end := off + 16\n        if end > len(data) {\n            end = len(data)\n        }\n        hexes := \"\"\n        txt := \"\"\n        for _, b := range data[off:end] {\n            hexes += fmt.Sprintf(\"%02x \", b)\n            if b >= 32 && b < 127 {\n                txt += string(rune(b))\n            } else {\n                txt += \".\"\n            }\n        }\n        sb.WriteString(fmt.Sprintf(\"%08x  %-48s |%s|\\n\", off, hexes, txt))\n    }\n    return sb.String()\n}\n\ntype @@PASCAL@@ struct {\n    sealed int\n}\n\nfunc (v *@@PASCAL@@) Seal(message string) []byte {\n    body := []byte(message)\n    blob := make([]byte, 8, 8+len(body))\n    binary.BigEndian.PutUint32(blob[0:4], magic)\n    binary.BigEndian.PutUint32(blob[4:8], fnv1a(body))\n    blob = append(blob, xorStream(body)...)\n    v.sealed++\n    return blob\n}\n\nfunc (v *@@PASCAL@@) Unseal(blob []byte) (string, error) {\n    if len(blob) < 8 {\n        return \"\", errors.New(\"short blob\")\n    }\n    if binary.BigEndian.Uint32(blob[0:4]) != magic {\n        return \"\", errors.New(\"bad magic\")\n    }\n    body := xorStream(blob[8:])\n    if fnv1a(body) != binary.BigEndian.Uint32(blob[4:8]) {\n        return \"\", errors.New(\"integrity check failed\")\n    }\n    return string(body), nil\n}\n\nfunc main() {\n    vault := &@@PASCAL@@{}\n    message := \"hello from @@SNAKE@@\"\n    if len(os.Args) > 1 {\n        message = strings.Join(os.Args[1:], \" \")\n    }\n    fmt.Println(\"starting @@SNAKE@@\")\n    blob := vault.Seal(message)\n    fmt.Print(hexdump(blob))\n    fmt.Printf(\"[+] sealed %d bytes, digest %08x\\n\", len(blob), fnv1a(blob))\n    plain, err := vault.Unseal(blob)\n    if err != nil {\n        fmt.Fprintln(os.Stderr, \"[!]\", err)\n        os.Exit(2)\n    }\n    fmt.Println(\"[+] opened:\", plain)\n}\n","templates/html.tpl":"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <title>@@PASCAL@@</title>\n  <style>\n    :root { --accent: #3b82f6; --bg: #f8fafc; --text: #0f172a; }\n    * { box-sizing: border-box; }\n    body {\n      margin: 0;\n      font-family: system-ui, sans-serif;\n      background: var(--bg);\n      color: var(--text);\n      display: grid;\n      place-items: center;\n      min-height: 100vh;\n    }\n    main { text-align: center; padding: 2rem; }\n    h1 { margin: 0 0 0.5rem; }\n    p { margin: 0 0 1.5rem; opacity: 0.7; }\n    button {\n      font: inherit;\n      padding: 0.6rem 1.2rem;\n      border: 0;\n      border-radius: 8px;\n      background: var(--accent);\n      color: white;\n      cursor: pointer;\n    }\n    button:hover { filter: brightness(1.1); }\n    #count { display: block; margin-top: 1rem; font-size: 2rem; font-weight: 600; }\n  </style>\n</head>\n<body>\n  <main>\n    <h1>@@PASCAL@@</h1>\n    <p>A small page generated from @@FILE@@.</p>\n    <button id=\"add\">Add one</button>\n    <span id=\"count\">0</span>\n  </main>\n  <script>\n    const button = document.getElementById('add');\n    const count = document.getElementById('count');\n    let total = 0;\n\n    button.addEventListener('click', () => {\n      total += 1;\n      count.textContent = String(total);\n    });\n  <\/script>\n</body>\n</html>\n","templates/java.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\nimport java.nio.ByteBuffer;\nimport java.nio.charset.StandardCharsets;\nimport java.util.Arrays;\n\npublic class @@CLASS@@ {\n    private static final int MAGIC = 0x@@MAGIC@@;\n    private static final int[] KEY = { @@KEYLIST@@ };\n\n    private int sealed = 0;\n\n    static int fnv1a(byte[] data) {\n        int h = 0x811C9DC5;\n        for (byte b : data) {\n            h ^= (b & 0xFF);\n            h *= 0x01000193;\n        }\n        return h;\n    }\n\n    static byte[] xorStream(byte[] in) {\n        byte[] out = new byte[in.length];\n        for (int i = 0; i < in.length; i++) {\n            out[i] = (byte) (in[i] ^ KEY[i % KEY.length] ^ (i & 0xFF));\n        }\n        return out;\n    }\n\n    static String hexdump(byte[] data) {\n        StringBuilder sb = new StringBuilder();\n        for (int off = 0; off < data.length; off += 16) {\n            sb.append(String.format(\"%08x  \", off));\n            StringBuilder txt = new StringBuilder();\n            for (int i = 0; i < 16; i++) {\n                if (off + i < data.length) {\n                    int b = data[off + i] & 0xFF;\n                    sb.append(String.format(\"%02x \", b));\n                    txt.append(b >= 32 && b < 127 ? (char) b : '.');\n                } else {\n                    sb.append(\"   \");\n                }\n            }\n            sb.append(\" |\").append(txt).append(\"|\\n\");\n        }\n        return sb.toString();\n    }\n\n    byte[] seal(String message) {\n        byte[] body = message.getBytes(StandardCharsets.UTF_8);\n        ByteBuffer buf = ByteBuffer.allocate(8 + body.length);\n        buf.putInt(MAGIC).putInt(fnv1a(body)).put(xorStream(body));\n        sealed++;\n        return buf.array();\n    }\n\n    String unseal(byte[] blob) {\n        ByteBuffer buf = ByteBuffer.wrap(blob);\n        if (buf.getInt() != MAGIC) throw new IllegalStateException(\"bad magic\");\n        int digest = buf.getInt();\n        byte[] body = xorStream(Arrays.copyOfRange(blob, 8, blob.length));\n        if (fnv1a(body) != digest) throw new IllegalStateException(\"integrity check failed\");\n        return new String(body, StandardCharsets.UTF_8);\n    }\n\n    public static void main(String[] args) {\n        @@CLASS@@ vault = new @@CLASS@@();\n        String message = args.length > 0 ? String.join(\" \", args) : \"hello from @@SNAKE@@\";\n        System.out.println(\"starting @@SNAKE@@\");\n        byte[] blob = vault.seal(message);\n        System.out.print(hexdump(blob));\n        System.out.printf(\"[+] sealed %d bytes, digest %08x%n\", blob.length, fnv1a(blob));\n        System.out.println(\"[+] opened: \" + vault.unseal(blob));\n    }\n}\n","templates/js.tpl":"#!/usr/bin/env node\n// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\n'use strict';\n\nconst KEY = Uint8Array.from([@@KEYLIST@@]);\nconst MAGIC = 0x@@MAGIC@@;\n\nfunction fnv1a(data) {\n  let h = 0x811c9dc5;\n  for (const b of data) {\n    h ^= b;\n    h = Math.imul(h, 0x01000193) >>> 0;\n  }\n  return h >>> 0;\n}\n\nfunction xorStream(data, key = KEY) {\n  const out = new Uint8Array(data.length);\n  for (let i = 0; i < data.length; i++) {\n    out[i] = data[i] ^ key[i % key.length] ^ (i & 0xff);\n  }\n  return out;\n}\n\nfunction hexdump(data, width = 16) {\n  const lines = [];\n  for (let off = 0; off < data.length; off += width) {\n    const chunk = data.slice(off, off + width);\n    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, '0')).join(' ');\n    const txt = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');\n    lines.push(off.toString(16).padStart(8, '0') + '  ' + hex.padEnd(width * 3) + ' |' + txt + '|');\n  }\n  return lines.join('\\n');\n}\n\nclass @@PASCAL@@ {\n  constructor(key = KEY) {\n    this.key = key;\n    this.sealed = 0;\n  }\n\n  seal(message) {\n    const body = new TextEncoder().encode(message);\n    const out = new Uint8Array(8 + body.length);\n    const view = new DataView(out.buffer);\n    view.setUint32(0, MAGIC);\n    view.setUint32(4, fnv1a(body));\n    out.set(xorStream(body, this.key), 8);\n    this.sealed++;\n    return out;\n  }\n\n  unseal(blob) {\n    const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);\n    if (view.getUint32(0) !== MAGIC) throw new Error('bad magic');\n    const body = xorStream(blob.slice(8), this.key);\n    if (fnv1a(body) !== view.getUint32(4)) throw new Error('integrity check failed');\n    return new TextDecoder().decode(body);\n  }\n}\n\nfunction main(argv) {\n  const vault = new @@PASCAL@@();\n  const message = argv.slice(2).join(' ') || 'hello from @@SNAKE@@';\n  console.log('starting @@SNAKE@@');\n  const blob = vault.seal(message);\n  console.log(hexdump(blob));\n  console.log('[+] sealed ' + blob.length + ' bytes, digest ' + fnv1a(blob).toString(16).padStart(8, '0'));\n  console.log('[+] opened: ' + vault.unseal(blob));\n  return 0;\n}\n\nprocess.exitCode = main(process.argv);\n","templates/lua.tpl":"-- @@FILE@@ :: @@BANNER@@\n-- build @@DATE@@\nlocal MAGIC = 0x@@MAGIC@@\nlocal KEY = { @@KEYLIST@@ }\n\nlocal function fnv1a(bytes)\n  local h = 0x811c9dc5\n  for _, b in ipairs(bytes) do\n    h = h ~ b\n    h = (h * 0x01000193) & 0xffffffff\n  end\n  return h\nend\n\nlocal function to_bytes(s)\n  return { s:byte(1, -1) }\nend\n\nlocal function xor_stream(bytes)\n  local out = {}\n  for i, b in ipairs(bytes) do\n    out[i] = b ~ KEY[(i - 1) % #KEY + 1] ~ ((i - 1) & 0xff)\n  end\n  return out\nend\n\nlocal function hexdump(bytes)\n  local lines = {}\n  for off = 1, #bytes, 16 do\n    local hex, txt = {}, {}\n    for i = off, math.min(off + 15, #bytes) do\n      hex[#hex + 1] = string.format(\"%02x\", bytes[i])\n      txt[#txt + 1] = (bytes[i] >= 32 and bytes[i] < 127) and string.char(bytes[i]) or \".\"\n    end\n    lines[#lines + 1] = string.format(\"%08x  %-48s |%s|\", off - 1, table.concat(hex, \" \"), table.concat(txt))\n  end\n  return table.concat(lines, \"\\n\")\nend\n\nlocal @@PASCAL@@ = {}\n@@PASCAL@@.__index = @@PASCAL@@\n\nfunction @@PASCAL@@.new()\n  return setmetatable({ sealed = 0 }, @@PASCAL@@)\nend\n\nfunction @@PASCAL@@:seal(message)\n  local body = to_bytes(message)\n  self.sealed = self.sealed + 1\n  return { magic = MAGIC, digest = fnv1a(body), body = xor_stream(body) }\nend\n\nfunction @@PASCAL@@:unseal(packet)\n  assert(packet.magic == MAGIC, \"bad magic\")\n  local body = xor_stream(packet.body)\n  assert(fnv1a(body) == packet.digest, \"integrity check failed\")\n  return string.char(table.unpack(body))\nend\n\nlocal vault = @@PASCAL@@.new()\nlocal message = table.concat(arg or {}, \" \")\nif message == \"\" then message = \"hello from @@SNAKE@@\" end\nprint(\"starting @@SNAKE@@\")\nlocal packet = vault:seal(message)\nprint(hexdump(packet.body))\nprint(string.format(\"[+] sealed %d bytes, digest %08x\", #packet.body + 8, packet.digest))\nprint(\"[+] opened: \" .. vault:unseal(packet))\n","templates/php.tpl":"<?php\n// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\ndeclare(strict_types=1);\n\nconst MAGIC = 0x@@MAGIC@@;\nconst KEY = [@@KEYLIST@@];\n\nfunction fnv1a(string $data): int\n{\n    $h = 0x811c9dc5;\n    foreach (unpack('C*', $data) ?: [] as $b) {\n        $h ^= $b;\n        $h = ($h * 0x01000193) & 0xffffffff;\n    }\n    return $h;\n}\n\nfunction xorStream(string $data): string\n{\n    $out = '';\n    $len = strlen($data);\n    for ($i = 0; $i < $len; $i++) {\n        $out .= chr(ord($data[$i]) ^ KEY[$i % count(KEY)] ^ ($i & 0xff));\n    }\n    return $out;\n}\n\nfunction hexdump(string $data, int $width = 16): string\n{\n    $lines = [];\n    foreach (str_split($data, $width) as $n => $chunk) {\n        $hex = implode(' ', str_split(bin2hex($chunk), 2));\n        $txt = preg_replace('/[^\\x20-\\x7e]/', '.', $chunk);\n        $lines[] = sprintf('%08x  %-48s |%s|', $n * $width, $hex, $txt);\n    }\n    return implode(\"\\n\", $lines);\n}\n\nfinal class @@PASCAL@@\n{\n    private int $sealed = 0;\n\n    public function seal(string $message): string\n    {\n        $this->sealed++;\n        return pack('NN', MAGIC, fnv1a($message)) . xorStream($message);\n    }\n\n    public function unseal(string $blob): string\n    {\n        $header = unpack('Nmagic/Ndigest', substr($blob, 0, 8));\n        if ($header['magic'] !== MAGIC) {\n            throw new RuntimeException('bad magic');\n        }\n        $body = xorStream(substr($blob, 8));\n        if (fnv1a($body) !== $header['digest']) {\n            throw new RuntimeException('integrity check failed');\n        }\n        return $body;\n    }\n}\n\n$vault = new @@PASCAL@@();\n$message = $argc > 1 ? implode(' ', array_slice($argv, 1)) : 'hello from @@SNAKE@@';\necho \"starting @@SNAKE@@\\n\";\n$blob = $vault->seal($message);\necho hexdump($blob), \"\\n\";\nprintf(\"[+] sealed %d bytes, digest %08x\\n\", strlen($blob), fnv1a($blob));\necho '[+] opened: ', $vault->unseal($blob), \"\\n\";\n","templates/py.tpl":"#!/usr/bin/env python3\n# @@FILE@@ :: @@BANNER@@\n# build @@DATE@@\n\"\"\"\n@@PASCAL@@: rolling-key XOR vault with FNV-1a integrity checking.\n\"\"\"\n\nimport struct\nimport sys\nimport time\n\nKEY = bytes([@@KEYLIST@@])\nMAGIC = 0x@@MAGIC@@\n\n\ndef fnv1a(data: bytes) -> int:\n    h = 0x811C9DC5\n    for b in data:\n        h ^= b\n        h = (h * 0x01000193) & 0xFFFFFFFF\n    return h\n\n\ndef xor_stream(data: bytes, key: bytes = KEY) -> bytes:\n    out = bytearray(len(data))\n    for i, b in enumerate(data):\n        out[i] = b ^ key[i % len(key)] ^ (i & 0xFF)\n    return bytes(out)\n\n\ndef hexdump(data: bytes, width: int = 16) -> str:\n    lines = []\n    for off in range(0, len(data), width):\n        chunk = data[off:off + width]\n        hexes = \" \".join(f\"{b:02x}\" for b in chunk)\n        text = \"\".join(chr(b) if 32 <= b < 127 else \".\" for b in chunk)\n        lines.append(f\"{off:08x}  {hexes:<{width * 3}} |{text}|\")\n    return \"\\n\".join(lines)\n\n\nclass @@PASCAL@@:\n    def __init__(self, key: bytes = KEY):\n        self.key = key\n        self.sealed = 0\n\n    def seal(self, message: str) -> bytes:\n        body = message.encode(\"utf-8\")\n        header = struct.pack(\">II\", MAGIC, fnv1a(body))\n        self.sealed += 1\n        return header + xor_stream(body, self.key)\n\n    def unseal(self, blob: bytes) -> str:\n        magic, digest = struct.unpack(\">II\", blob[:8])\n        if magic != MAGIC:\n            raise ValueError(\"bad magic\")\n        body = xor_stream(blob[8:], self.key)\n        if fnv1a(body) != digest:\n            raise ValueError(\"integrity check failed\")\n        return body.decode(\"utf-8\")\n\n\ndef main(argv: list) -> int:\n    vault = @@PASCAL@@()\n    message = \" \".join(argv[1:]) or \"hello from @@SNAKE@@\"\n    print(\"starting @@SNAKE@@\")\n    time.sleep(0.2)\n    blob = vault.seal(message)\n    print(hexdump(blob))\n    print(f\"[+] sealed {len(blob)} bytes, digest {fnv1a(blob):08x}\")\n    print(f\"[+] opened: {vault.unseal(blob)}\")\n    return 0\n\n\nif __name__ == \"__main__\":\n    sys.exit(main(sys.argv))\n","templates/rb.tpl":"#!/usr/bin/env ruby\n# @@FILE@@ :: @@BANNER@@\n# build @@DATE@@\n\nMAGIC = 0x@@MAGIC@@\nKEY = [@@KEYLIST@@].freeze\n\ndef fnv1a(bytes)\n  h = 0x811c9dc5\n  bytes.each do |b|\n    h ^= b\n    h = (h * 0x01000193) & 0xffffffff\n  end\n  h\nend\n\ndef xor_stream(bytes)\n  bytes.each_with_index.map { |b, i| b ^ KEY[i % KEY.length] ^ (i & 0xff) }\nend\n\ndef hexdump(bytes, width = 16)\n  bytes.each_slice(width).with_index.map do |chunk, n|\n    hex = chunk.map { |b| format('%02x', b) }.join(' ')\n    txt = chunk.map { |b| b.between?(32, 126) ? b.chr : '.' }.join\n    format('%08x  %-48s |%s|', n * width, hex, txt)\n  end.join(\"\\n\")\nend\n\nclass @@PASCAL@@\n  attr_reader :sealed\n\n  def initialize\n    @sealed = 0\n  end\n\n  def seal(message)\n    body = message.bytes\n    @sealed += 1\n    [MAGIC, fnv1a(body)].pack('NN').bytes + xor_stream(body)\n  end\n\n  def unseal(blob)\n    magic, digest = blob[0, 8].pack('C*').unpack('NN')\n    raise 'bad magic' unless magic == MAGIC\n\n    body = xor_stream(blob[8..])\n    raise 'integrity check failed' unless fnv1a(body) == digest\n\n    body.pack('C*').force_encoding('UTF-8')\n  end\nend\n\nvault = @@PASCAL@@.new\nmessage = ARGV.empty? ? 'hello from @@SNAKE@@' : ARGV.join(' ')\nputs 'starting @@SNAKE@@'\nblob = vault.seal(message)\nputs hexdump(blob)\nputs format('[+] sealed %d bytes, digest %08x', blob.length, fnv1a(blob))\nputs \"[+] opened: #{vault.unseal(blob)}\"\n","templates/rs.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\nuse std::env;\nuse std::process;\n\nconst MAGIC: u32 = 0x@@MAGIC@@;\nconst KEY: [u8; @@KEYLEN@@] = [@@KEYLIST@@];\n\nfn fnv1a(data: &[u8]) -> u32 {\n    let mut h: u32 = 0x811c9dc5;\n    for &b in data {\n        h ^= b as u32;\n        h = h.wrapping_mul(0x01000193);\n    }\n    h\n}\n\nfn xor_stream(input: &[u8]) -> Vec<u8> {\n    input\n        .iter()\n        .enumerate()\n        .map(|(i, &b)| b ^ KEY[i % KEY.len()] ^ (i & 0xff) as u8)\n        .collect()\n}\n\nfn hexdump(data: &[u8]) -> String {\n    let mut out = String::new();\n    for (n, chunk) in data.chunks(16).enumerate() {\n        let hex: Vec<String> = chunk.iter().map(|b| format!(\"{:02x}\", b)).collect();\n        let txt: String = chunk\n            .iter()\n            .map(|&b| if (32..127).contains(&b) { b as char } else { '.' })\n            .collect();\n        out.push_str(&format!(\"{:08x}  {:<48} |{}|\\n\", n * 16, hex.join(\" \"), txt));\n    }\n    out\n}\n\nstruct @@PASCAL@@ {\n    sealed: usize,\n}\n\nimpl @@PASCAL@@ {\n    fn new() -> Self {\n        Self { sealed: 0 }\n    }\n\n    fn seal(&mut self, message: &str) -> Vec<u8> {\n        let body = message.as_bytes();\n        let mut blob = Vec::with_capacity(8 + body.len());\n        blob.extend_from_slice(&MAGIC.to_be_bytes());\n        blob.extend_from_slice(&fnv1a(body).to_be_bytes());\n        blob.extend(xor_stream(body));\n        self.sealed += 1;\n        blob\n    }\n\n    fn unseal(&self, blob: &[u8]) -> Result<String, String> {\n        if blob.len() < 8 {\n            return Err(\"short blob\".to_string());\n        }\n        let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);\n        let digest = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);\n        if magic != MAGIC {\n            return Err(\"bad magic\".to_string());\n        }\n        let body = xor_stream(&blob[8..]);\n        if fnv1a(&body) != digest {\n            return Err(\"integrity check failed\".to_string());\n        }\n        String::from_utf8(body).map_err(|e| e.to_string())\n    }\n}\n\nfn main() {\n    let args: Vec<String> = env::args().skip(1).collect();\n    let message = if args.is_empty() {\n        \"hello from @@SNAKE@@\".to_string()\n    } else {\n        args.join(\" \")\n    };\n    let mut vault = @@PASCAL@@::new();\n    println!(\"starting @@SNAKE@@\");\n    let blob = vault.seal(&message);\n    print!(\"{}\", hexdump(&blob));\n    println!(\"[+] sealed {} bytes, digest {:08x}\", blob.len(), fnv1a(&blob));\n    match vault.unseal(&blob) {\n        Ok(plain) => println!(\"[+] opened: {}\", plain),\n        Err(e) => {\n            eprintln!(\"[!] {}\", e);\n            process::exit(2);\n        }\n    }\n}\n","templates/sh.tpl":"#!/usr/bin/env bash\n# @@FILE@@ :: @@BANNER@@\n# build @@DATE@@\nset -euo pipefail\n\nKEY=(@@KEYLIST_SPACE@@)\nMAGIC=0x@@MAGIC@@\n\nfnv1a() {\n    local h=$((0x811c9dc5))\n    local b\n    for b in \"$@\"; do\n        h=$(( ((h ^ b) * 0x01000193) & 0xffffffff ))\n    done\n    echo \"$h\"\n}\n\nbytes_of() {\n    # print every byte of the argument as a decimal number\n    printf '%s' \"$1\" | od -An -v -tu1 | tr -s ' ' '\\n' | sed '/^$/d'\n}\n\nxor_stream() {\n    local i=0 b\n    for b in \"$@\"; do\n        echo $(( b ^ KEY[i % ${#KEY[@]}] ^ (i & 255) ))\n        i=$((i + 1))\n    done\n}\n\nto_hex() {\n    local b out=\"\"\n    for b in \"$@\"; do\n        out+=$(printf '%02x ' \"$b\")\n    done\n    echo \"$out\"\n}\n\nmain() {\n    local message=\"${*:-hello from @@SNAKE@@}\"\n    echo \"starting @@SNAKE@@\"\n    local body=($(bytes_of \"$message\"))\n    local digest\n    digest=$(fnv1a \"${body[@]}\")\n    local sealed=($(xor_stream \"${body[@]}\"))\n    printf '[+] header  magic=%08x digest=%08x\\n' \"$MAGIC\" \"$digest\"\n    echo \"[+] cipher  $(to_hex \"${sealed[@]}\")\"\n    local opened=($(xor_stream \"${sealed[@]}\"))\n    if [[ \"$(fnv1a \"${opened[@]}\")\" != \"$digest\" ]]; then\n        echo \"[!] integrity check failed\" >&2\n        return 2\n    fi\n    local text=\"\" b\n    for b in \"${opened[@]}\"; do\n        text+=$(printf \"\\\\$(printf '%03o' \"$b\")\")\n    done\n    echo \"[+] opened: $text\"\n}\n\nmain \"$@\"\n","templates/ts.tpl":"// @@FILE@@ :: @@BANNER@@\n// build @@DATE@@\n\ndeclare const process: { argv: string[]; exitCode?: number };\n\nconst KEY: number[] = [@@KEYLIST@@];\nconst MAGIC = 0x@@MAGIC@@;\n\ninterface Packet {\n  magic: number;\n  digest: number;\n  body: Uint8Array;\n}\n\nfunction fnv1a(data: Uint8Array): number {\n  let h = 0x811c9dc5;\n  for (let i = 0; i < data.length; i++) {\n    h ^= data[i];\n    h = Math.imul(h, 0x01000193) >>> 0;\n  }\n  return h >>> 0;\n}\n\nfunction xorStream(data: Uint8Array): Uint8Array {\n  const out = new Uint8Array(data.length);\n  for (let i = 0; i < data.length; i++) {\n    out[i] = data[i] ^ KEY[i % KEY.length] ^ (i & 0xff);\n  }\n  return out;\n}\n\nfunction hexdump(data: Uint8Array, width = 16): string {\n  const lines: string[] = [];\n  for (let off = 0; off < data.length; off += width) {\n    const chunk = Array.from(data.slice(off, off + width));\n    const hex = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ');\n    const txt = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');\n    lines.push(off.toString(16).padStart(8, '0') + '  ' + hex.padEnd(width * 3) + ' |' + txt + '|');\n  }\n  return lines.join('\\n');\n}\n\nclass @@PASCAL@@ {\n  private sealed = 0;\n\n  seal(message: string): Packet {\n    const body = new TextEncoder().encode(message);\n    this.sealed++;\n    return { magic: MAGIC, digest: fnv1a(body), body: xorStream(body) };\n  }\n\n  unseal(packet: Packet): string {\n    if (packet.magic !== MAGIC) throw new Error('bad magic');\n    const body = xorStream(packet.body);\n    if (fnv1a(body) !== packet.digest) throw new Error('integrity check failed');\n    return new TextDecoder().decode(body);\n  }\n\n  get count(): number {\n    return this.sealed;\n  }\n}\n\nfunction main(argv: string[]): number {\n  const vault = new @@PASCAL@@();\n  const message = argv.slice(2).join(' ') || 'hello from @@SNAKE@@';\n  console.log('starting @@SNAKE@@');\n  const packet = vault.seal(message);\n  console.log(hexdump(packet.body));\n  console.log('[+] sealed ' + (packet.body.length + 8) + ' bytes, digest ' + packet.digest.toString(16).padStart(8, '0'));\n  console.log('[+] opened: ' + vault.unseal(packet));\n  return vault.count > 0 ? 0 : 1;\n}\n\nprocess.exitCode = main(process.argv);\n","templates/programs/donut.c":"#include <stdio.h>\n#include <math.h>\n#include <string.h>\n#include <unistd.h>\n\nint main() {\n    float A = 0, B = 0;\n    float i, j;\n    int k;\n    float z[1760];\n    char b[1760];\n    printf(\"\\x1b[2J\");\n    for (;;) {\n        memset(b, 32, 1760);\n        memset(z, 0, 7040);\n        for (j = 0; j < 6.28; j += 0.07) {\n            for (i = 0; i < 6.28; i += 0.02) {\n                float c = sin(i);\n                float d = cos(j);\n                float e = sin(A);\n                float f = sin(j);\n                float g = cos(A);\n                float h = d + 2;\n                float D = 1 / (c * h * e + f * g + 5);\n                float l = cos(i);\n                float m = cos(B);\n                float n = sin(B);\n                float t = c * h * g - f * e;\n                int x = 40 + 30 * D * (l * h * m - t * n);\n                int y = 12 + 15 * D * (l * h * n + t * m);\n                int o = x + 80 * y;\n                int N = 8 * ((f * e - c * d * g) * m - c * d * e - f * g - l * d * n);\n                if (22 > y && y > 0 && x > 0 && 80 > x && D > z[o]) {\n                    z[o] = D;\n                    b[o] = \".,-~:;=!*#$@\"[N > 0 ? N : 0];\n                }\n            }\n        }\n        printf(\"\\x1b[H\");\n        for (k = 0; k < 1761; k++) {\n            putchar(k % 80 ? b[k] : 10);\n            A += 0.00004;\n            B += 0.00002;\n        }\n        usleep(30000);\n    }\n    return 0;\n}\n","templates/programs/donut.js":"// Spinning ASCII donut. Run with: node @@FILE@@\nconst SHADES = '.,-~:;=!*#$@';\nlet A = 0;\nlet B = 0;\n\nprocess.stdout.write('\\x1b[2J');\n\nfunction frame() {\n  const b = new Array(1760).fill(' ');\n  const z = new Array(1760).fill(0);\n  for (let j = 0; j < 6.28; j += 0.07) {\n    for (let i = 0; i < 6.28; i += 0.02) {\n      const c = Math.sin(i);\n      const d = Math.cos(j);\n      const e = Math.sin(A);\n      const f = Math.sin(j);\n      const g = Math.cos(A);\n      const h = d + 2;\n      const D = 1 / (c * h * e + f * g + 5);\n      const l = Math.cos(i);\n      const m = Math.cos(B);\n      const n = Math.sin(B);\n      const t = c * h * g - f * e;\n      const x = Math.floor(40 + 30 * D * (l * h * m - t * n));\n      const y = Math.floor(12 + 15 * D * (l * h * n + t * m));\n      const o = x + 80 * y;\n      const N = Math.floor(8 * ((f * e - c * d * g) * m - c * d * e - f * g - l * d * n));\n      if (y > 0 && y < 22 && x > 0 && x < 80 && D > z[o]) {\n        z[o] = D;\n        b[o] = SHADES[Math.min(Math.max(N, 0), SHADES.length - 1)];\n      }\n    }\n  }\n  let out = '\\x1b[H';\n  for (let k = 0; k < 1760; k++) {\n    out += k % 80 ? b[k] : '\\n';\n  }\n  process.stdout.write(out);\n  A += 0.07;\n  B += 0.035;\n}\n\nsetInterval(frame, 40);\n","templates/programs/donut.py":"import math\nimport sys\nimport time\n\nSHADES = \".,-~:;=!*#$@\"\n\n\ndef main():\n    A = 0.0\n    B = 0.0\n    sys.stdout.write(\"\\x1b[2J\")\n    while True:\n        b = [\" \"] * 1760\n        z = [0.0] * 1760\n        for j in range(0, 628, 7):\n            theta = j / 100\n            for i in range(0, 628, 2):\n                phi = i / 100\n                c = math.sin(phi)\n                d = math.cos(theta)\n                e = math.sin(A)\n                f = math.sin(theta)\n                g = math.cos(A)\n                h = d + 2\n                D = 1 / (c * h * e + f * g + 5)\n                l = math.cos(phi)\n                m = math.cos(B)\n                n = math.sin(B)\n                t = c * h * g - f * e\n                x = int(40 + 30 * D * (l * h * m - t * n))\n                y = int(12 + 15 * D * (l * h * n + t * m))\n                o = x + 80 * y\n                N = int(8 * ((f * e - c * d * g) * m - c * d * e - f * g - l * d * n))\n                if 22 > y > 0 and 0 < x < 80 and D > z[o]:\n                    z[o] = D\n                    b[o] = SHADES[min(max(N, 0), len(SHADES) - 1)]\n        out = \"\\x1b[H\"\n        for k in range(1760):\n            out += b[k] if k % 80 else \"\\n\"\n        sys.stdout.write(out)\n        sys.stdout.flush()\n        A += 0.07\n        B += 0.035\n        time.sleep(0.03)\n\n\nif __name__ == \"__main__\":\n    try:\n        main()\n    except KeyboardInterrupt:\n        sys.stdout.write(\"\\x1b[0m\\n\")\n","templates/programs/fibonacci.c":"#include <stdio.h>\n\nunsigned long long fib(int n) {\n    unsigned long long a = 0, b = 1;\n    for (int i = 0; i < n; i++) {\n        unsigned long long t = a + b;\n        a = b;\n        b = t;\n    }\n    return a;\n}\n\nint main(void) {\n    for (int i = 0; i < 40; i++) {\n        printf(\"fib(%d) = %llu\\n\", i, fib(i));\n    }\n    return 0;\n}\n","templates/programs/fibonacci.cpp":"#include <cstdint>\n#include <iostream>\n\nstd::uint64_t fib(int n) {\n    std::uint64_t a = 0, b = 1;\n    for (int i = 0; i < n; ++i) {\n        std::uint64_t t = a + b;\n        a = b;\n        b = t;\n    }\n    return a;\n}\n\nint main() {\n    for (int i = 0; i < 40; ++i) {\n        std::cout << \"fib(\" << i << \") = \" << fib(i) << \"\\n\";\n    }\n    return 0;\n}\n","templates/programs/fibonacci.cs":"using System;\n\ninternal static class Program\n{\n    private static ulong Fib(int n)\n    {\n        ulong a = 0, b = 1;\n        for (var i = 0; i < n; i++)\n        {\n            var t = a + b;\n            a = b;\n            b = t;\n        }\n        return a;\n    }\n\n    private static void Main()\n    {\n        for (var i = 0; i < 40; i++)\n        {\n            Console.WriteLine(\"fib(\" + i + \") = \" + Fib(i));\n        }\n    }\n}\n","templates/programs/fibonacci.go":"package main\n\nimport \"fmt\"\n\nfunc fib(n int) uint64 {\n    var a, b uint64 = 0, 1\n    for i := 0; i < n; i++ {\n        a, b = b, a+b\n    }\n    return a\n}\n\nfunc main() {\n    for i := 0; i < 40; i++ {\n        fmt.Printf(\"fib(%d) = %d\\n\", i, fib(i))\n    }\n}\n","templates/programs/fibonacci.java":"public class @@CLASS@@ {\n    static long fib(int n) {\n        long a = 0, b = 1;\n        for (int i = 0; i < n; i++) {\n            long t = a + b;\n            a = b;\n            b = t;\n        }\n        return a;\n    }\n\n    public static void main(String[] args) {\n        for (int i = 0; i < 40; i++) {\n            System.out.println(\"fib(\" + i + \") = \" + fib(i));\n        }\n    }\n}\n","templates/programs/fibonacci.js":"function fib(n) {\n  let a = 0n;\n  let b = 1n;\n  for (let i = 0; i < n; i++) {\n    [a, b] = [b, a + b];\n  }\n  return a;\n}\n\nfor (let i = 0; i < 40; i++) {\n  console.log('fib(' + i + ') = ' + fib(i));\n}\n","templates/programs/fibonacci.lua":"local function fib(n)\n  local a, b = 0, 1\n  for _ = 1, n do\n    a, b = b, a + b\n  end\n  return a\nend\n\nfor i = 0, 39 do\n  print(string.format(\"fib(%d) = %d\", i, fib(i)))\nend\n","templates/programs/fibonacci.php":"<?php\nfunction fib(int $n): int\n{\n    [$a, $b] = [0, 1];\n    for ($i = 0; $i < $n; $i++) {\n        [$a, $b] = [$b, $a + $b];\n    }\n    return $a;\n}\n\nfor ($i = 0; $i < 40; $i++) {\n    echo \"fib($i) = \" . fib($i) . \"\\n\";\n}\n","templates/programs/fibonacci.py":"def fib(n: int) -> int:\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\n\ndef main():\n    for i in range(40):\n        print(f\"fib({i}) = {fib(i)}\")\n\n\nif __name__ == \"__main__\":\n    main()\n","templates/programs/fibonacci.rb":"def fib(n)\n  a, b = 0, 1\n  n.times { a, b = b, a + b }\n  a\nend\n\n40.times do |i|\n  puts \"fib(#{i}) = #{fib(i)}\"\nend\n","templates/programs/fibonacci.rs":"fn fib(n: u32) -> u64 {\n    let (mut a, mut b) = (0u64, 1u64);\n    for _ in 0..n {\n        let t = a + b;\n        a = b;\n        b = t;\n    }\n    a\n}\n\nfn main() {\n    for i in 0..40 {\n        println!(\"fib({}) = {}\", i, fib(i));\n    }\n}\n","templates/programs/fibonacci.sh":"#!/usr/bin/env bash\nfib() {\n    local n=$1 a=0 b=1 t i\n    for ((i = 0; i < n; i++)); do\n        t=$((a + b))\n        a=$b\n        b=$t\n    done\n    echo \"$a\"\n}\n\nfor i in $(seq 0 39); do\n    echo \"fib($i) = $(fib \"$i\")\"\ndone\n","templates/programs/fibonacci.ts":"function fib(n: number): bigint {\n  let a = 0n;\n  let b = 1n;\n  for (let i = 0; i < n; i++) {\n    [a, b] = [b, a + b];\n  }\n  return a;\n}\n\nfor (let i = 0; i < 40; i++) {\n  console.log('fib(' + i + ') = ' + fib(i));\n}\n","templates/programs/fizzbuzz.c":"#include <stdio.h>\n\nint main(void) {\n    for (int i = 1; i <= 100; i++) {\n        if (i % 15 == 0) puts(\"FizzBuzz\");\n        else if (i % 3 == 0) puts(\"Fizz\");\n        else if (i % 5 == 0) puts(\"Buzz\");\n        else printf(\"%d\\n\", i);\n    }\n    return 0;\n}\n","templates/programs/fizzbuzz.cpp":"#include <iostream>\n\nint main() {\n    for (int i = 1; i <= 100; ++i) {\n        if (i % 15 == 0) std::cout << \"FizzBuzz\\n\";\n        else if (i % 3 == 0) std::cout << \"Fizz\\n\";\n        else if (i % 5 == 0) std::cout << \"Buzz\\n\";\n        else std::cout << i << \"\\n\";\n    }\n    return 0;\n}\n","templates/programs/fizzbuzz.cs":"using System;\n\ninternal static class Program\n{\n    private static string FizzBuzz(int n)\n    {\n        if (n % 15 == 0) return \"FizzBuzz\";\n        if (n % 3 == 0) return \"Fizz\";\n        if (n % 5 == 0) return \"Buzz\";\n        return n.ToString();\n    }\n\n    private static void Main()\n    {\n        for (var i = 1; i <= 100; i++)\n        {\n            Console.WriteLine(FizzBuzz(i));\n        }\n    }\n}\n","templates/programs/fizzbuzz.go":"package main\n\nimport \"fmt\"\n\nfunc fizzbuzz(n int) string {\n    switch {\n    case n%15 == 0:\n        return \"FizzBuzz\"\n    case n%3 == 0:\n        return \"Fizz\"\n    case n%5 == 0:\n        return \"Buzz\"\n    }\n    return fmt.Sprint(n)\n}\n\nfunc main() {\n    for i := 1; i <= 100; i++ {\n        fmt.Println(fizzbuzz(i))\n    }\n}\n","templates/programs/fizzbuzz.java":"public class @@CLASS@@ {\n    static String fizzbuzz(int n) {\n        if (n % 15 == 0) return \"FizzBuzz\";\n        if (n % 3 == 0) return \"Fizz\";\n        if (n % 5 == 0) return \"Buzz\";\n        return Integer.toString(n);\n    }\n\n    public static void main(String[] args) {\n        for (int i = 1; i <= 100; i++) {\n            System.out.println(fizzbuzz(i));\n        }\n    }\n}\n","templates/programs/fizzbuzz.js":"function fizzbuzz(n) {\n  if (n % 15 === 0) return 'FizzBuzz';\n  if (n % 3 === 0) return 'Fizz';\n  if (n % 5 === 0) return 'Buzz';\n  return String(n);\n}\n\nfor (let i = 1; i <= 100; i++) {\n  console.log(fizzbuzz(i));\n}\n","templates/programs/fizzbuzz.lua":"local function fizzbuzz(n)\n  if n % 15 == 0 then return \"FizzBuzz\" end\n  if n % 3 == 0 then return \"Fizz\" end\n  if n % 5 == 0 then return \"Buzz\" end\n  return tostring(n)\nend\n\nfor i = 1, 100 do\n  print(fizzbuzz(i))\nend\n","templates/programs/fizzbuzz.php":"<?php\nfunction fizzbuzz(int $n): string\n{\n    if ($n % 15 === 0) {\n        return 'FizzBuzz';\n    }\n    if ($n % 3 === 0) {\n        return 'Fizz';\n    }\n    if ($n % 5 === 0) {\n        return 'Buzz';\n    }\n    return (string) $n;\n}\n\nfor ($i = 1; $i <= 100; $i++) {\n    echo fizzbuzz($i), \"\\n\";\n}\n","templates/programs/fizzbuzz.py":"def fizzbuzz(n: int) -> str:\n    if n % 15 == 0:\n        return \"FizzBuzz\"\n    if n % 3 == 0:\n        return \"Fizz\"\n    if n % 5 == 0:\n        return \"Buzz\"\n    return str(n)\n\n\nif __name__ == \"__main__\":\n    for i in range(1, 101):\n        print(fizzbuzz(i))\n","templates/programs/fizzbuzz.rb":"def fizzbuzz(n)\n  return 'FizzBuzz' if (n % 15).zero?\n  return 'Fizz' if (n % 3).zero?\n  return 'Buzz' if (n % 5).zero?\n\n  n.to_s\nend\n\n(1..100).each { |i| puts fizzbuzz(i) }\n","templates/programs/fizzbuzz.rs":"fn fizzbuzz(n: u32) -> String {\n    match (n % 3, n % 5) {\n        (0, 0) => \"FizzBuzz\".to_string(),\n        (0, _) => \"Fizz\".to_string(),\n        (_, 0) => \"Buzz\".to_string(),\n        _ => n.to_string(),\n    }\n}\n\nfn main() {\n    for i in 1..=100 {\n        println!(\"{}\", fizzbuzz(i));\n    }\n}\n","templates/programs/fizzbuzz.sh":"#!/usr/bin/env bash\nfor i in $(seq 1 100); do\n    if ((i % 15 == 0)); then\n        echo \"FizzBuzz\"\n    elif ((i % 3 == 0)); then\n        echo \"Fizz\"\n    elif ((i % 5 == 0)); then\n        echo \"Buzz\"\n    else\n        echo \"$i\"\n    fi\ndone\n","templates/programs/fizzbuzz.ts":"function fizzbuzz(n: number): string {\n  if (n % 15 === 0) return 'FizzBuzz';\n  if (n % 3 === 0) return 'Fizz';\n  if (n % 5 === 0) return 'Buzz';\n  return String(n);\n}\n\nfor (let i = 1; i <= 100; i++) {\n  console.log(fizzbuzz(i));\n}\n","templates/programs/hello.c":"#include <stdio.h>\n\nint main(void) {\n    printf(\"Hello, World!\\n\");\n    return 0;\n}\n","templates/programs/hello.cpp":"#include <iostream>\n\nint main() {\n    std::cout << \"Hello, World!\" << std::endl;\n    return 0;\n}\n","templates/programs/hello.cs":"using System;\n\ninternal static class Program\n{\n    private static void Main()\n    {\n        Console.WriteLine(\"Hello, World!\");\n    }\n}\n","templates/programs/hello.go":"package main\n\nimport \"fmt\"\n\nfunc main() {\n    fmt.Println(\"Hello, World!\")\n}\n","templates/programs/hello.java":"public class @@CLASS@@ {\n    public static void main(String[] args) {\n        System.out.println(\"Hello, World!\");\n    }\n}\n","templates/programs/hello.js":"console.log('Hello, World!');\n","templates/programs/hello.lua":"print(\"Hello, World!\")\n","templates/programs/hello.php":"<?php\necho \"Hello, World!\\n\";\n","templates/programs/hello.py":"def main():\n    print(\"Hello, World!\")\n\n\nif __name__ == \"__main__\":\n    main()\n","templates/programs/hello.rb":"puts 'Hello, World!'\n","templates/programs/hello.rs":"fn main() {\n    println!(\"Hello, World!\");\n}\n","templates/programs/hello.sh":"#!/usr/bin/env bash\necho \"Hello, World!\"\n","templates/programs/hello.ts":"const greeting: string = 'Hello, World!';\nconsole.log(greeting);\n","templates/programs/life.c":"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <time.h>\n#include <unistd.h>\n\n#define W 60\n#define H 24\n\nstatic int grid[H][W];\nstatic int next_grid[H][W];\n\nstatic int neighbours(int y, int x) {\n    int n = 0;\n    for (int dy = -1; dy <= 1; dy++) {\n        for (int dx = -1; dx <= 1; dx++) {\n            if (dy || dx) n += grid[(y + dy + H) % H][(x + dx + W) % W];\n        }\n    }\n    return n;\n}\n\nint main(void) {\n    srand((unsigned)time(NULL));\n    for (int y = 0; y < H; y++)\n        for (int x = 0; x < W; x++)\n            grid[y][x] = rand() % 4 == 0;\n\n    printf(\"\\x1b[2J\");\n    for (;;) {\n        printf(\"\\x1b[H\");\n        for (int y = 0; y < H; y++) {\n            for (int x = 0; x < W; x++) putchar(grid[y][x] ? '#' : ' ');\n            putchar('\\n');\n        }\n        for (int y = 0; y < H; y++) {\n            for (int x = 0; x < W; x++) {\n                int n = neighbours(y, x);\n                next_grid[y][x] = grid[y][x] ? (n == 2 || n == 3) : (n == 3);\n            }\n        }\n        memcpy(grid, next_grid, sizeof grid);\n        usleep(80000);\n    }\n    return 0;\n}\n","templates/programs/life.js":"// Conway's Game of Life. Run with: node @@FILE@@\nconst W = 60;\nconst H = 24;\n\nlet grid = Array.from({ length: H }, () => Array.from({ length: W }, () => (Math.random() < 0.25 ? 1 : 0)));\n\nfunction neighbours(y, x) {\n  let n = 0;\n  for (let dy = -1; dy <= 1; dy++) {\n    for (let dx = -1; dx <= 1; dx++) {\n      if (dy || dx) n += grid[(y + dy + H) % H][(x + dx + W) % W];\n    }\n  }\n  return n;\n}\n\nfunction step() {\n  grid = grid.map((row, y) =>\n    row.map((cell, x) => {\n      const n = neighbours(y, x);\n      return n === 3 || (cell && n === 2) ? 1 : 0;\n    })\n  );\n}\n\nprocess.stdout.write('\\x1b[2J');\nsetInterval(() => {\n  process.stdout.write('\\x1b[H' + grid.map((row) => row.map((c) => (c ? '#' : ' ')).join('')).join('\\n') + '\\n');\n  step();\n}, 80);\n","templates/programs/life.py":"import random\nimport sys\nimport time\n\nW, H = 60, 24\n\n\ndef step(grid):\n    nxt = [[0] * W for _ in range(H)]\n    for y in range(H):\n        for x in range(W):\n            n = sum(\n                grid[(y + dy) % H][(x + dx) % W]\n                for dy in (-1, 0, 1)\n                for dx in (-1, 0, 1)\n                if dy or dx\n            )\n            nxt[y][x] = 1 if (n == 3 or (grid[y][x] and n == 2)) else 0\n    return nxt\n\n\ndef main():\n    grid = [[1 if random.random() < 0.25 else 0 for _ in range(W)] for _ in range(H)]\n    sys.stdout.write(\"\\x1b[2J\")\n    while True:\n        sys.stdout.write(\"\\x1b[H\" + \"\\n\".join(\"\".join(\"#\" if c else \" \" for c in row) for row in grid) + \"\\n\")\n        sys.stdout.flush()\n        grid = step(grid)\n        time.sleep(0.08)\n\n\nif __name__ == \"__main__\":\n    try:\n        main()\n    except KeyboardInterrupt:\n        pass\n","templates/programs/mandelbrot.c":"#include <stdio.h>\n\nint main(void) {\n    const char *shades = \" .:-=+*#%@\";\n    const int max_iter = 100;\n\n    for (int row = 0; row < 24; row++) {\n        for (int col = 0; col < 80; col++) {\n            double cr = (col - 55) / 25.0;\n            double ci = (row - 12) / 9.0;\n            double zr = 0.0, zi = 0.0;\n            int n = 0;\n            while (n < max_iter && zr * zr + zi * zi < 4.0) {\n                double t = zr * zr - zi * zi + cr;\n                zi = 2.0 * zr * zi + ci;\n                zr = t;\n                n++;\n            }\n            putchar(shades[n == max_iter ? 9 : n % 9]);\n        }\n        putchar('\\n');\n    }\n    return 0;\n}\n","templates/programs/mandelbrot.js":"const SHADES = ' .:-=+*#%@';\nconst MAX_ITER = 100;\n\nfunction escapeTime(cr, ci) {\n  let zr = 0;\n  let zi = 0;\n  let n = 0;\n  while (n < MAX_ITER && zr * zr + zi * zi < 4) {\n    const t = zr * zr - zi * zi + cr;\n    zi = 2 * zr * zi + ci;\n    zr = t;\n    n++;\n  }\n  return n;\n}\n\nfor (let row = 0; row < 24; row++) {\n  let line = '';\n  for (let col = 0; col < 80; col++) {\n    const n = escapeTime((col - 55) / 25, (row - 12) / 9);\n    line += SHADES[n === MAX_ITER ? 9 : n % 9];\n  }\n  console.log(line);\n}\n","templates/programs/mandelbrot.py":"SHADES = \" .:-=+*#%@\"\nMAX_ITER = 100\n\n\ndef escape_time(cr: float, ci: float) -> int:\n    zr = zi = 0.0\n    n = 0\n    while n < MAX_ITER and zr * zr + zi * zi < 4.0:\n        zr, zi = zr * zr - zi * zi + cr, 2.0 * zr * zi + ci\n        n += 1\n    return n\n\n\ndef main():\n    for row in range(24):\n        line = \"\"\n        for col in range(80):\n            n = escape_time((col - 55) / 25.0, (row - 12) / 9.0)\n            line += SHADES[9 if n == MAX_ITER else n % 9]\n        print(line)\n\n\nif __name__ == \"__main__\":\n    main()\n","templates/programs/matrix.c":"#include <stdio.h>\n#include <stdlib.h>\n#include <time.h>\n#include <unistd.h>\n\n#define COLS 80\n#define ROWS 24\n\nstatic char glyph(void) {\n    return (char)(33 + rand() % 94);\n}\n\nint main(void) {\n    int drop[COLS];\n    int tail[COLS];\n\n    srand((unsigned)time(NULL));\n    for (int x = 0; x < COLS; x++) {\n        drop[x] = -(rand() % ROWS);\n        tail[x] = 6 + rand() % 12;\n    }\n\n    printf(\"\\x1b[2J\\x1b[?25l\");\n    for (;;) {\n        for (int x = 0; x < COLS; x++) {\n            int y = drop[x];\n            if (y >= 0 && y < ROWS) printf(\"\\x1b[%d;%dH\\x1b[97m%c\", y + 1, x + 1, glyph());\n            if (y - 1 >= 0 && y - 1 < ROWS) printf(\"\\x1b[%d;%dH\\x1b[32m%c\", y, x + 1, glyph());\n            int end = y - tail[x];\n            if (end >= 0 && end < ROWS) printf(\"\\x1b[%d;%dH \", end + 1, x + 1);\n            drop[x]++;\n            if (drop[x] - tail[x] > ROWS && rand() % 20 == 0) {\n                drop[x] = 0;\n                tail[x] = 6 + rand() % 12;\n            }\n        }\n        fflush(stdout);\n        usleep(60000);\n    }\n    return 0;\n}\n","templates/programs/matrix.js":"// Digital rain. Run with: node @@FILE@@  (Ctrl-C to exit)\nconst GLYPHS = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ0123456789ABCDEF';\nconst cols = process.stdout.columns || 80;\nconst rows = process.stdout.rows || 24;\nconst rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));\nconst glyph = () => GLYPHS[rnd(0, GLYPHS.length - 1)];\n\nconst drops = Array.from({ length: cols }, () => rnd(-rows, 0));\nconst tails = Array.from({ length: cols }, () => rnd(6, 18));\n\nprocess.stdout.write('\\x1b[2J\\x1b[?25l');\n\nconst timer = setInterval(() => {\n  let frame = '';\n  for (let x = 0; x < cols; x++) {\n    const y = drops[x];\n    if (y >= 0 && y < rows) frame += '\\x1b[' + (y + 1) + ';' + (x + 1) + 'H\\x1b[97m' + glyph();\n    if (y - 1 >= 0 && y - 1 < rows) frame += '\\x1b[' + y + ';' + (x + 1) + 'H\\x1b[32m' + glyph();\n    const end = y - tails[x];\n    if (end >= 0 && end < rows) frame += '\\x1b[' + (end + 1) + ';' + (x + 1) + 'H ';\n    drops[x]++;\n    if (drops[x] - tails[x] > rows && Math.random() > 0.95) {\n      drops[x] = 0;\n      tails[x] = rnd(6, 18);\n    }\n  }\n  process.stdout.write(frame);\n}, 50);\n\nprocess.on('SIGINT', () => {\n  clearInterval(timer);\n  process.stdout.write('\\x1b[0m\\x1b[?25h\\x1b[2J\\x1b[H');\n  process.exit(0);\n});\n","templates/programs/matrix.py":"import random\nimport shutil\nimport sys\nimport time\n\nGLYPHS = \"ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ0123456789ABCDEF\"\n\n\ndef main():\n    cols, rows = shutil.get_terminal_size()\n    drops = [random.randint(-rows, 0) for _ in range(cols)]\n    tails = [random.randint(6, 18) for _ in range(cols)]\n    sys.stdout.write(\"\\x1b[2J\\x1b[?25l\")\n    try:\n        while True:\n            frame = []\n            for x in range(cols):\n                y = drops[x]\n                if 0 <= y < rows:\n                    frame.append(f\"\\x1b[{y + 1};{x + 1}H\\x1b[97m{random.choice(GLYPHS)}\")\n                if 0 <= y - 1 < rows:\n                    frame.append(f\"\\x1b[{y};{x + 1}H\\x1b[32m{random.choice(GLYPHS)}\")\n                end = y - tails[x]\n                if 0 <= end < rows:\n                    frame.append(f\"\\x1b[{end + 1};{x + 1}H \")\n                drops[x] += 1\n                if drops[x] - tails[x] > rows and random.random() > 0.95:\n                    drops[x] = 0\n                    tails[x] = random.randint(6, 18)\n            sys.stdout.write(\"\".join(frame))\n            sys.stdout.flush()\n            time.sleep(0.05)\n    except KeyboardInterrupt:\n        pass\n    finally:\n        sys.stdout.write(\"\\x1b[0m\\x1b[?25h\\x1b[2J\\x1b[H\")\n\n\nif __name__ == \"__main__\":\n    main()\n","templates/programs/primes.c":"#include <stdio.h>\n#include <stdlib.h>\n\nint main(int argc, char **argv) {\n    int limit = argc > 1 ? atoi(argv[1]) : 100;\n    if (limit < 2) return 0;\n\n    char *composite = calloc(limit + 1, 1);\n    for (int i = 2; (long)i * i <= limit; i++) {\n        if (composite[i]) continue;\n        for (int j = i * i; j <= limit; j += i) composite[j] = 1;\n    }\n\n    int count = 0;\n    for (int i = 2; i <= limit; i++) {\n        if (!composite[i]) {\n            printf(\"%d \", i);\n            count++;\n        }\n    }\n    printf(\"\\n%d primes up to %d\\n\", count, limit);\n    free(composite);\n    return 0;\n}\n","templates/programs/primes.cpp":"#include <cstdlib>\n#include <iostream>\n#include <vector>\n\nint main(int argc, char** argv) {\n    int limit = argc > 1 ? std::atoi(argv[1]) : 100;\n    std::vector<bool> composite(limit + 1, false);\n    int count = 0;\n\n    for (int i = 2; i <= limit; ++i) {\n        if (composite[i]) continue;\n        std::cout << i << ' ';\n        ++count;\n        for (long long j = static_cast<long long>(i) * i; j <= limit; j += i) {\n            composite[j] = true;\n        }\n    }\n    std::cout << \"\\n\" << count << \" primes up to \" << limit << \"\\n\";\n    return 0;\n}\n","templates/programs/primes.cs":"using System;\nusing System.Collections.Generic;\n\ninternal static class Program\n{\n    private static List<int> Sieve(int limit)\n    {\n        var composite = new bool[limit + 1];\n        var primes = new List<int>();\n        for (var i = 2; i <= limit; i++)\n        {\n            if (composite[i]) continue;\n            primes.Add(i);\n            for (long j = (long)i * i; j <= limit; j += i) composite[j] = true;\n        }\n        return primes;\n    }\n\n    private static void Main(string[] args)\n    {\n        var limit = args.Length > 0 ? int.Parse(args[0]) : 100;\n        var primes = Sieve(limit);\n        Console.WriteLine(string.Join(\" \", primes));\n        Console.WriteLine(primes.Count + \" primes up to \" + limit);\n    }\n}\n","templates/programs/primes.go":"package main\n\nimport (\n    \"fmt\"\n    \"os\"\n    \"strconv\"\n)\n\nfunc sieve(limit int) []int {\n    composite := make([]bool, limit+1)\n    var primes []int\n    for i := 2; i <= limit; i++ {\n        if composite[i] {\n            continue\n        }\n        primes = append(primes, i)\n        for j := i * i; j <= limit; j += i {\n            composite[j] = true\n        }\n    }\n    return primes\n}\n\nfunc main() {\n    limit := 100\n    if len(os.Args) > 1 {\n        if n, err := strconv.Atoi(os.Args[1]); err == nil {\n            limit = n\n        }\n    }\n    primes := sieve(limit)\n    fmt.Println(primes)\n    fmt.Printf(\"%d primes up to %d\\n\", len(primes), limit)\n}\n","templates/programs/primes.java":"import java.util.ArrayList;\nimport java.util.List;\n\npublic class @@CLASS@@ {\n    static List<Integer> sieve(int limit) {\n        boolean[] composite = new boolean[limit + 1];\n        List<Integer> primes = new ArrayList<>();\n        for (int i = 2; i <= limit; i++) {\n            if (composite[i]) continue;\n            primes.add(i);\n            for (long j = (long) i * i; j <= limit; j += i) composite[(int) j] = true;\n        }\n        return primes;\n    }\n\n    public static void main(String[] args) {\n        int limit = args.length > 0 ? Integer.parseInt(args[0]) : 100;\n        List<Integer> primes = sieve(limit);\n        System.out.println(primes);\n        System.out.println(primes.size() + \" primes up to \" + limit);\n    }\n}\n","templates/programs/primes.js":"function sieve(limit) {\n  const composite = new Array(limit + 1).fill(false);\n  const primes = [];\n  for (let i = 2; i <= limit; i++) {\n    if (composite[i]) continue;\n    primes.push(i);\n    for (let j = i * i; j <= limit; j += i) composite[j] = true;\n  }\n  return primes;\n}\n\nconst limit = Number(process.argv[2]) || 100;\nconst primes = sieve(limit);\nconsole.log(primes.join(' '));\nconsole.log(primes.length + ' primes up to ' + limit);\n","templates/programs/primes.lua":"local function sieve(limit)\n  local composite, primes = {}, {}\n  for i = 2, limit do\n    if not composite[i] then\n      primes[#primes + 1] = i\n      for j = i * i, limit, i do\n        composite[j] = true\n      end\n    end\n  end\n  return primes\nend\n\nlocal limit = tonumber(arg and arg[1]) or 100\nlocal primes = sieve(limit)\nprint(table.concat(primes, \" \"))\nprint(#primes .. \" primes up to \" .. limit)\n","templates/programs/primes.php":"<?php\nfunction sieve(int $limit): array\n{\n    $composite = array_fill(0, $limit + 1, false);\n    $primes = [];\n    for ($i = 2; $i <= $limit; $i++) {\n        if ($composite[$i]) {\n            continue;\n        }\n        $primes[] = $i;\n        for ($j = $i * $i; $j <= $limit; $j += $i) {\n            $composite[$j] = true;\n        }\n    }\n    return $primes;\n}\n\n$limit = (int) ($argv[1] ?? 100);\n$primes = sieve($limit);\necho implode(' ', $primes), \"\\n\";\necho count($primes) . \" primes up to $limit\\n\";\n","templates/programs/primes.py":"import sys\n\n\ndef sieve(limit: int) -> list:\n    composite = [False] * (limit + 1)\n    primes = []\n    for i in range(2, limit + 1):\n        if composite[i]:\n            continue\n        primes.append(i)\n        for j in range(i * i, limit + 1, i):\n            composite[j] = True\n    return primes\n\n\ndef main():\n    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100\n    primes = sieve(limit)\n    print(\" \".join(map(str, primes)))\n    print(f\"{len(primes)} primes up to {limit}\")\n\n\nif __name__ == \"__main__\":\n    main()\n","templates/programs/primes.rb":"def sieve(limit)\n  composite = Array.new(limit + 1, false)\n  primes = []\n  (2..limit).each do |i|\n    next if composite[i]\n\n    primes << i\n    (i * i).step(limit, i) { |j| composite[j] = true }\n  end\n  primes\nend\n\nlimit = (ARGV[0] || 100).to_i\nprimes = sieve(limit)\nputs primes.join(' ')\nputs \"#{primes.length} primes up to #{limit}\"\n","templates/programs/primes.rs":"use std::env;\n\nfn sieve(limit: usize) -> Vec<usize> {\n    let mut composite = vec![false; limit + 1];\n    let mut primes = Vec::new();\n    for i in 2..=limit {\n        if composite[i] {\n            continue;\n        }\n        primes.push(i);\n        let mut j = i * i;\n        while j <= limit {\n            composite[j] = true;\n            j += i;\n        }\n    }\n    primes\n}\n\nfn main() {\n    let limit: usize = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(100);\n    let primes = sieve(limit);\n    println!(\"{:?}\", primes);\n    println!(\"{} primes up to {}\", primes.len(), limit);\n}\n","templates/programs/primes.sh":"#!/usr/bin/env bash\nlimit=${1:-100}\ncount=0\nfor ((n = 2; n <= limit; n++)); do\n    is_prime=1\n    for ((d = 2; d * d <= n; d++)); do\n        if ((n % d == 0)); then\n            is_prime=0\n            break\n        fi\n    done\n    if ((is_prime)); then\n        printf '%d ' \"$n\"\n        count=$((count + 1))\n    fi\ndone\nprintf '\\n%d primes up to %d\\n' \"$count\" \"$limit\"\n","templates/programs/primes.ts":"declare const process: { argv: string[] };\n\nfunction sieve(limit: number): number[] {\n  const composite: boolean[] = new Array(limit + 1).fill(false);\n  const primes: number[] = [];\n  for (let i = 2; i <= limit; i++) {\n    if (composite[i]) continue;\n    primes.push(i);\n    for (let j = i * i; j <= limit; j += i) composite[j] = true;\n  }\n  return primes;\n}\n\nconst limit = Number(process.argv[2]) || 100;\nconst primes = sieve(limit);\nconsole.log(primes.join(' '));\nconsole.log(primes.length + ' primes up to ' + limit);\n"};
function __dir(id) { var i = id.lastIndexOf('/'); return i < 0 ? '' : id.slice(0, i); }
function __norm(p) { var out = []; p.split('/').forEach(function (s) { if (!s || s === '.') return; if (s === '..') out.pop(); else out.push(s); }); return out.join('/'); }
function __key(p) { var s = String(p); var i = s.indexOf('templates/'); return i < 0 ? s : s.slice(i); }
var __shim = {
  path: { join: function () { return __norm(Array.prototype.join.call(arguments, '/')); }, basename: function (p) { return String(p).split('/').pop(); } },
  fs: {
    readFileSync: function (p) { var k = __key(p); if (!(k in __FILES)) throw new Error('ENOENT: ' + p); return __FILES[k]; },
    existsSync: function (p) { return __key(p) in __FILES; }
  }
};
function __require(from, req) {
  if (req === 'path' || req === 'fs') return __shim[req];
  if (req === 'vscode') return require('vscode');
  var id = __norm(__dir(from) + '/' + req);
  if (!__mods[id]) { if (__mods[id + '.js']) id += '.js'; else if (__mods[id + '/index.js']) id += '/index.js'; else throw new Error('Cannot find module ' + req + ' from ' + from); }
  if (__cache[id]) return __cache[id].exports;
  var m = { exports: {} };
  __cache[id] = m;
  __mods[id](m, m.exports, function (r) { return __require(id, r); });
  return m.exports;
}

__mods["lib/generator.js"] = function (module, exports, require) {
'use strict';
// Turns a file name (e.g. "app.py") into source code.
// No dependency on the vscode module, so it can be tested with plain node.

const fs = require('fs');
const path = require('path');

const ALIASES = {
  mjs: 'js', cjs: 'js', jsx: 'js', tsx: 'ts', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
  h: 'c', bash: 'sh', zsh: 'sh', pyw: 'py', htm: 'html',
};

const LANG_NAMES = {
  py: 'Python', js: 'JavaScript', ts: 'TypeScript', c: 'C', cpp: 'C++', java: 'Java',
  go: 'Go', rs: 'Rust', rb: 'Ruby', php: 'PHP', sh: 'Bash', cs: 'C#', lua: 'Lua',
  html: 'HTML', kt: 'Kotlin', swift: 'Swift', pl: 'Perl', sql: 'SQL', ps1: 'PowerShell',
  r: 'R', dart: 'Dart', scala: 'Scala', hs: 'Haskell', asm: 'x86 assembly', css: 'CSS',
  zig: 'Zig', ex: 'Elixir', jl: 'Julia', m: 'Objective-C', vb: 'Visual Basic',
};

const COMMENT_PREFIX = {
  py: '#', rb: '#', sh: '#', bash: '#', zsh: '#', pl: '#', r: '#', ps1: '#', yml: '#',
  yaml: '#', toml: '#', jl: '#', ex: '#', lua: '--', sql: '--', hs: '--', asm: ';',
  s: ';', lisp: ';', clj: ';', vb: "'",
};

const LANGUAGE_CHOICES = [
  { label: 'Python', ext: 'py' }, { label: 'JavaScript', ext: 'js' },
  { label: 'TypeScript', ext: 'ts' }, { label: 'C', ext: 'c' },
  { label: 'C++', ext: 'cpp' }, { label: 'Java', ext: 'java' },
  { label: 'Go', ext: 'go' }, { label: 'Rust', ext: 'rs' },
  { label: 'Ruby', ext: 'rb' }, { label: 'PHP', ext: 'php' },
  { label: 'Bash', ext: 'sh' }, { label: 'C#', ext: 'cs' },
  { label: 'Lua', ext: 'lua' }, { label: 'HTML', ext: 'html' },
  { label: 'Other', ext: 'txt' },
];

const RESERVED = new Set([
  'main', 'int', 'char', 'class', 'new', 'return', 'void', 'static', 'if', 'for', 'while',
  'struct', 'default', 'fn', 'let', 'type', 'func', 'package', 'import', 'end', 'def',
]);
const CLASH = new Set(['Program', 'Main', 'Key', 'Magic', 'String', 'System', 'Console', 'Vault']);


function splitName(fileName) {
  const base = path.basename(fileName);
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return { stem: base, ext: '' };
  return { stem: base.slice(0, dot), ext: base.slice(dot + 1).toLowerCase() };
}

function hashString(s) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function languageName(ext) {
  return LANG_NAMES[ext] || (ext ? ext.toUpperCase() : 'plain text');
}

function buildVars(fileName) {
  const { stem, ext } = splitName(fileName);
  const rng = mulberry32(hashString(fileName));

  let words = stem.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (!words.length) words = ['sample'];
  const cap = (w) => w[0].toUpperCase() + w.slice(1).toLowerCase();

  let pascal = words.map(cap).join('');
  if (/^\d/.test(pascal)) pascal = 'X' + pascal;
  if (CLASH.has(pascal)) pascal += 'Core';
  let snake = words.join('_').toLowerCase();
  if (/^\d/.test(snake)) snake = 'x_' + snake;
  if (RESERVED.has(snake)) snake += '_x';

  const keyBytes = Array.from({ length: 8 }, () => 0x10 + Math.floor(rng() * 0xee));
  const hex = (n) => '0x' + n.toString(16).padStart(2, '0');
  const magic = Math.floor(rng() * 0xffffffff).toString(16).padStart(8, '0');
  const tplExt = ALIASES[ext] || ext;

  return {
    ext, tplExt,
    vars: {
      FILE: path.basename(fileName),
      PASCAL: pascal,
      CAMEL: pascal[0].toLowerCase() + pascal.slice(1),
      SNAKE: snake,
      UPPER: snake.toUpperCase(),
      CLASS: /^[A-Za-z_][A-Za-z0-9_]*$/.test(stem) ? stem : pascal,
      BANNER: pascal + ' utility',
      DATE: new Date().toISOString().slice(0, 10),
      MAGIC: magic,
      KEYLIST: keyBytes.map(hex).join(', '),
      KEYLIST_SPACE: keyBytes.map(hex).join(' '),
      KEYLEN: String(keyBytes.length),
      C: COMMENT_PREFIX[ext] || '//',
      HOST: '10.' + Math.floor(rng() * 250) + '.' + Math.floor(rng() * 250) + '.' + (1 + Math.floor(rng() * 250)),
      PORT: String(1024 + Math.floor(rng() * 60000)),
      PID: String(100 + Math.floor(rng() * 9000)),
    },
  };
}

function normalize(code) {
  return code.replace(/\r\n/g, '\n').replace(/^\s*\n/, '').replace(/\s+$/, '') + '\n';
}

function fill(file, vars, tplExt) {
  let code = fs.readFileSync(file, 'utf8').replace(/@@([A-Z_]+)@@/g, (m, k) => (k in vars ? vars[k] : m));
  if (tplExt === 'go') {
    // gofmt style: tabs for indentation
    code = code.replace(/^( {4})+/gm, (m) => '\t'.repeat(m.length / 4));
  }
  return normalize(code);
}

/** Render the generic built-in template (the XOR "vault") for fileName. */
function render(extensionPath, fileName) {
  const { tplExt, vars } = buildVars(fileName);
  let file = path.join(extensionPath, 'templates', tplExt + '.tpl');
  if (!tplExt || !fs.existsSync(file)) file = path.join(extensionPath, 'templates', 'generic.tpl');
  return { code: fill(file, vars, tplExt), template: path.basename(file) };
}

// Well-known programs, matched by words in the file name (donut.c, my_matrix.py ...).
const PROGRAMS = {
  donut: ['donut', 'doughnut', 'torus'],
  matrix: ['matrix', 'rain', 'neo'],
  mandelbrot: ['mandelbrot', 'mandel', 'fractal'],
  life: ['life', 'conway', 'gol', 'gameoflife'],
  fizzbuzz: ['fizzbuzz', 'fizz', 'buzz'],
  fibonacci: ['fib', 'fibonacci', 'fibo'],
  primes: ['prime', 'primes', 'sieve'],
  hello: ['hello', 'helloworld', 'world'],
};

/** Find a built-in program that matches the name AND exists for this language, or null. */
function renderProgram(extensionPath, fileName) {
  const { stem } = splitName(fileName);
  const { tplExt, vars } = buildVars(fileName);
  if (!tplExt) return null;
  const tokens = stem.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const compact = tokens.join('');
  for (const [prog, keys] of Object.entries(PROGRAMS)) {
    const hit = keys.some((k) => tokens.includes(k) || (k.length >= 5 && compact.includes(k)));
    if (!hit) continue;
    const file = path.join(extensionPath, 'templates', 'programs', prog + '.' + tplExt);
    if (fs.existsSync(file)) return { code: fill(file, vars, tplExt), program: prog };
  }
  return null;
}

module.exports = { splitName, render, renderProgram, languageName, normalize, LANGUAGE_CHOICES };

};
__mods["lib/typist.js"] = function (module, exports, require) {
'use strict';
// A tiny model of "a person typing in VS Code", one key press per step().
// No dependency on the vscode module, so it can be tested with plain node.
//
// It reproduces the editor behaviours people actually see while typing:
//   * typing  (  [  {  "  '  inserts the PAIR and leaves the cursor between them
//   * typing the closer when it is already there just steps over it ("overtype")
//   * pressing Enter between {} () [] expands the block onto three lines
//   * when the body is done, the closer is already waiting on the next line, so
//     one "arrow down / End" key press hops over it
//   * human mistakes (wrong key, doubled letter, swapped letters, shift fumble)
//     that later key presses backspace and fix

const KEY_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm'];

function neighbourOf(ch, rng = Math.random) {
  const lower = ch.toLowerCase();
  for (const row of KEY_ROWS) {
    const i = row.indexOf(lower);
    if (i === -1) continue;
    const options = [];
    if (i > 0) options.push(row[i - 1]);
    if (i < row.length - 1) options.push(row[i + 1]);
    const pick = options[Math.floor(rng() * options.length)];
    return ch === lower ? pick : pick.toUpperCase();
  }
  return ch;
}

const OPENERS = { '(': ')', '[': ']', '{': '}' };
const CLOSERS = ')]}';
const QUOTES = ['"', "'", '`'];
// VS Code only auto-closes when the next character is one of these (or end of line).
const AUTO_CLOSE_BEFORE = ';:.,=}])> \n\t';

const HASH_LANGS = new Set(['py', 'pyw', 'rb', 'sh', 'bash', 'zsh', 'pl', 'r', 'ps1', 'yml', 'yaml', 'toml', 'jl', 'ex']);
const DASH_LANGS = new Set(['lua', 'sql', 'hs']);
const BACKTICK_LANGS = new Set(['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'go']);

function langConfig(ext) {
  ext = (ext || '').toLowerCase();
  if (ext === 'html' || ext === 'htm') {
    return { hash: false, dash: false, slash: false, lexQuotes: [], autoQuotes: false, backtickPairs: false };
  }
  const lexQuotes = ['"', "'"];
  if (BACKTICK_LANGS.has(ext)) lexQuotes.push('`');
  return {
    hash: HASH_LANGS.has(ext),
    dash: DASH_LANGS.has(ext),
    slash: !HASH_LANGS.has(ext) && !DASH_LANGS.has(ext),
    lexQuotes,
    autoQuotes: true,
    backtickPairs: ext === 'js' || ext === 'jsx' || ext === 'mjs' || ext === 'cjs' || ext === 'ts' || ext === 'tsx',
  };
}

/** Knows whether the text typed so far ended inside a string or a comment. */
class Lexer {
  constructor(cfg) {
    this.cfg = cfg;
    this.s = { mode: 'code', quote: null, esc: false };
    this.prev = undefined;
  }

  advance(ch) {
    const s = this.s;
    const cfg = this.cfg;
    if (s.mode === 'line') {
      if (ch === '\n') s.mode = 'code';
      this.prev = ch;
      return;
    }
    if (s.mode === 'block') {
      if (this.prev === '*' && ch === '/') { s.mode = 'code'; this.prev = undefined; } else this.prev = ch;
      return;
    }
    if (s.mode === 'str') {
      if (s.esc) s.esc = false;
      else if (ch === '\\' && s.quote !== '`') s.esc = true;
      else if (ch === s.quote) s.mode = 'code';
      this.prev = ch;
      return;
    }
    if (cfg.hash && ch === '#' && (this.prev === undefined || /[\s;]/.test(this.prev))) { s.mode = 'line'; this.prev = ch; return; }
    if (cfg.slash && this.prev === '/' && ch === '/') { s.mode = 'line'; this.prev = ch; return; }
    if (cfg.slash && this.prev === '/' && ch === '*') { s.mode = 'block'; this.prev = undefined; return; }
    if (cfg.dash && this.prev === '-' && ch === '-') { s.mode = 'line'; this.prev = ch; return; }
    if (cfg.lexQuotes.includes(ch)) { s.mode = 'str'; s.quote = ch; s.esc = false; }
    this.prev = ch;
  }
}

class Typist {
  /**
   * @param {string} code  the file that should exist when typing is finished
   * @param {string} ext   file extension, e.g. "c" or "py" (drives comment/string rules)
   * @param {{typoRate?: number, rng?: () => number}} opts
   */
  constructor(code, ext, opts = {}) {
    this.code = code;
    this.chars = Array.from(code);
    this.pos = 0;            // next intended character
    this.doc = '';           // simulated document text
    this.cursor = 0;         // simulated cursor offset
    this.queue = [];         // pending micro-actions (typo sequences)
    this.skipTypoAt = -1;
    this.typoRate = opts.typoRate === undefined ? 0.035 : opts.typoRate;
    this.rng = opts.rng || Math.random;
    this.cfg = langConfig(ext);
    this.lex = new Lexer(this.cfg);
  }

  get done() { return this.pos >= this.chars.length && this.queue.length === 0; }
  get progress() { return this.chars.length ? this.pos / this.chars.length : 1; }
  get tail() { return this.doc.slice(this.cursor); }

  _randInt(a, b) { return a + Math.floor(this.rng() * (b - a + 1)); }

  _edit(text, cursorAdvance) {
    const at = this.cursor;
    this.doc = this.doc.slice(0, at) + text + this.doc.slice(at);
    this.cursor += cursorAdvance;
    return { at, text };
  }

  _consume(n = 1) {
    for (let i = 0; i < n && this.pos < this.chars.length; i++) {
      this.lex.advance(this.chars[this.pos]);
      this.pos++;
    }
  }

  /**
   * Perform ONE key press.
   * Returns { op, cursor, kind, ch, notice?, blankNext? } where op is
   * { at, text } (insert), { at, del } (delete) or null (cursor movement only).
   * Returns null when there is nothing left to do.
   */
  step() {
    if (!this.queue.length) {
      if (this.pos >= this.chars.length) return null;
      this._refill();
    }
    const a = this.queue.shift();

    if (a.ins !== undefined) {
      const op = this._edit(a.ins, a.ins.length);
      return { op, cursor: this.cursor, kind: 'type', ch: a.ins };
    }
    if (a.del) {
      if (this.cursor === 0) return { op: null, cursor: this.cursor, kind: 'del', ch: '' };
      const at = this.cursor - 1;
      this.doc = this.doc.slice(0, at) + this.doc.slice(this.cursor);
      this.cursor = at;
      return { op: { at, del: 1 }, cursor: this.cursor, kind: 'del', ch: '', notice: !!a.notice };
    }
    return this._key();
  }

  // ---- human mistakes -------------------------------------------------------

  _refill() {
    const ch = this.chars[this.pos];
    const isLetter = (c) => c !== undefined && /[A-Za-z]/.test(c);

    if (this.typoRate > 0 && isLetter(ch) && this.pos !== this.skipTypoAt && this.rng() < this.typoRate) {
      const roll = this.rng();
      const nextCh = this.chars[this.pos + 1];
      const swapCase = (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase());

      if (roll < 0.2) {
        // Held the key a hair too long: doubled letter, noticed immediately.
        this.queue.push({ ins: ch }, { ins: ch }, { del: true, notice: true });
        this.lex.advance(ch);
        this.pos++;
        return;
      }

      let wrong;
      if (roll < 0.4 && isLetter(nextCh)) wrong = [nextCh, ch];       // "teh" for "the"
      else if (roll < 0.55) wrong = [swapCase(ch)];                    // shift fumble
      else wrong = [neighbourOf(ch, this.rng)];                        // wrong key
      if (wrong.length === 1 && wrong[0] === ch) wrong = [swapCase(ch)];

      // Sleepy: sometimes keeps typing 0-3 more characters before noticing.
      const extra = [];
      const maxExtra = [0, 0, 1, 1, 2, 3][this._randInt(0, 5)];
      let k = this.pos + (wrong.length === 2 ? 2 : 1);
      while (extra.length < maxExtra && k < this.chars.length && /[A-Za-z0-9_]/.test(this.chars[k])) extra.push(this.chars[k++]);

      for (const c of wrong.concat(extra)) this.queue.push({ ins: c });
      const total = wrong.length + extra.length;
      for (let n = 0; n < total; n++) this.queue.push({ del: true, notice: n === 0 });
      this.skipTypoAt = this.pos;
      return;
    }
    this.queue.push({ key: true });
  }

  // ---- the normal "type the next character" key press -----------------------

  _canAutoCloseBracket() {
    const tail = this.tail;
    return tail === '' || AUTO_CLOSE_BEFORE.includes(tail[0]);
  }

  _canAutoCloseQuote(q) {
    if (!this.cfg.autoQuotes) return false;
    if (q === '`' && !this.cfg.backtickPairs) return false;
    if (this.lex.s.mode !== 'code') return false;
    const before = this.doc[this.cursor - 1] || '';
    if (before === q) return false;
    if (q === "'" && /\w/.test(before)) return false; // apostrophe inside a word
    return this._canAutoCloseBracket();
  }

  _key() {
    const ch = this.chars[this.pos];
    if (ch === '\n') return this._enter();

    const escaped = this.lex.s.mode === 'str' && this.lex.s.esc;
    const tail = this.tail;

    // The closer is already there: step over it.
    if (!escaped && (CLOSERS.includes(ch) || QUOTES.includes(ch)) && tail[0] === ch) {
      this.cursor += 1;
      this._consume(1);
      return { op: null, cursor: this.cursor, kind: 'overtype', ch };
    }

    // Opening bracket: the editor adds the closer for us.
    if (OPENERS[ch] && this._canAutoCloseBracket()) {
      const op = this._edit(ch + OPENERS[ch], 1);
      this._consume(1);
      return { op, cursor: this.cursor, kind: 'autoclose', ch };
    }
    if (QUOTES.includes(ch) && !escaped && this._canAutoCloseQuote(ch)) {
      const op = this._edit(ch + ch, 1);
      this._consume(1);
      return { op, cursor: this.cursor, kind: 'autoclose', ch };
    }

    const op = this._edit(ch, ch.length);
    this._consume(1);
    return { op, cursor: this.cursor, kind: 'type', ch };
  }

  _enter() {
    const chars = this.chars;
    let j = this.pos + 1;
    while (j < chars.length && (chars[j] === ' ' || chars[j] === '\t')) j++;
    const ws = chars.slice(this.pos + 1, j).join('');
    const nextCh = chars[j];
    const blankNext = chars[this.pos + 1] === '\n';
    const tail = this.tail;

    // 1) The body is finished and its closer is already waiting on the next line:
    //    one "arrow down / End" key press hops over it.
    if (nextCh && CLOSERS.includes(nextCh)) {
      const m = /^\n[ \t]*/.exec(tail);
      if (m && tail[m[0].length] === nextCh) {
        this.cursor += m[0].length + 1;
        this._consume(j - this.pos + 1);
        return { op: null, cursor: this.cursor, kind: 'skip', ch: nextCh };
      }
    }

    // 2) Enter between a fresh {} () [] expands the block onto three lines.
    const lastCh = this.doc[this.cursor - 1];
    const wantedCloser = OPENERS[lastCh];
    if (wantedCloser && tail[0] === wantedCloser && nextCh !== wantedCloser) {
      const lineStart = this.doc.lastIndexOf('\n', this.cursor - 1) + 1;
      const closerIndent = /^[ \t]*/.exec(this.doc.slice(lineStart, this.cursor))[0];
      const op = this._edit('\n' + ws + '\n' + closerIndent, 1 + ws.length);
      this._consume(j - this.pos);
      return { op, cursor: this.cursor, kind: 'enter', ch: '\n', blankNext };
    }

    // 3) Plain Enter. The editor keeps the indentation going.
    const op = this._edit('\n' + ws, 1 + ws.length);
    this._consume(j - this.pos);
    return { op, cursor: this.cursor, kind: 'enter', ch: '\n', blankNext };
  }
}

module.exports = { Typist, neighbourOf };

};
__mods["lib/ai/index.js"] = function (module, exports, require) {
'use strict';
// The "mini AI": reads a file name, works out what the script is probably
// about, picks a program shape that suits it, and compiles that program to the
// requested language.
//
//   name  ->  tokens  ->  theme pack + program shape  ->  IR program  ->  source code
//
// It is rule based (a vocabulary of ~600 words plus fuzzy matching), so it is
// instant and offline. For names it does not know, it invents a theme out of
// the name's own words.

const path = require('path');
const { PACKS, ARCHE_WORDS, GENERIC } = require('./lexicon');
const A = require('./archetypes');
const { emit, SUPPORTED } = require('./emit');

const EXT_ALIASES = { mjs: 'js', cjs: 'js', jsx: 'js', tsx: 'ts', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', h: 'c', pyw: 'py', htm: 'html' };

const STOP = new Set(['test', 'tests', 'main', 'app', 'script', 'new', 'file', 'untitled', 'temp', 'tmp', 'code', 'program', 'demo',
  'sample', 'project', 'final', 'copy', 'my', 'the', 'a', 'an', 'of', 'and', 'for', 'to', 'in', 'is', 'v', 'old', 'good', 'best', 'cool',
  'ur', 'your', 'you', 'i', 'it', 'on', 'at', 'with', 'tool', 'util', 'utils', 'helper', 'thing', 'stuff', 'run', 'start', 'go']);

// word -> pack key / archetype key lookups
const WORD_PACK = new Map();
for (const [key, p] of Object.entries(PACKS)) for (const w of p.words) if (!WORD_PACK.has(w)) WORD_PACK.set(w, key);
const WORD_ARCHE = new Map();
for (const [key, list] of Object.entries(ARCHE_WORDS)) for (const w of list) if (!WORD_ARCHE.has(w)) WORD_ARCHE.set(w, key);
const ALL_WORDS = [...new Set([...WORD_PACK.keys(), ...WORD_ARCHE.keys()])];

function hash(s) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}

/** Damerau-Levenshtein, bounded: returns > max as soon as it is clearly too far. */
function distance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = [];
  for (let i = 0; i <= a.length; i++) { d[i] = [i]; }
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

function tokenize(stem) {
  return stem
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/([A-Za-z])(\d)/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t && !/^\d+$/.test(t));
}

/** Look one token up: exact, simple plural/suffix forms, then typo-tolerant. */
function lookup(token) {
  const forms = [token];
  if (token.endsWith('ies')) forms.push(token.slice(0, -3) + 'y');
  if (token.endsWith('es')) forms.push(token.slice(0, -2));
  if (token.endsWith('s')) forms.push(token.slice(0, -1));
  if (token.endsWith('ing')) forms.push(token.slice(0, -3), token.slice(0, -3) + 'e');
  if (token.endsWith('er')) forms.push(token.slice(0, -2));
  for (const f of forms) {
    if (WORD_PACK.has(f) || WORD_ARCHE.has(f)) return { word: f, pack: WORD_PACK.get(f), arche: WORD_ARCHE.get(f), how: 'exact' };
  }
  if (token.length >= 5) {
    const max = token.length >= 9 ? 2 : 1;
    let best = null;
    for (const w of ALL_WORDS) {
      if (w.length < 5) continue;
      const dist = distance(token, w, max);
      if (dist <= max && (!best || dist < best.dist)) best = { w, dist };
    }
    if (best) return { word: best.w, pack: WORD_PACK.get(best.w), arche: WORD_ARCHE.get(best.w), how: 'fuzzy' };
  }
  return null;
}

function titleCase(words) {
  return words.map((w) => w[0].toUpperCase() + w.slice(1)).join(' ');
}

/** Make a theme out of the name's own words when no pack matches. */
function deriveTheme(tokens) {
  const words = tokens.filter((t) => !STOP.has(t));
  const use = words.length ? words : ['sample'];
  const caps = use.map((w) => w[0].toUpperCase() + w.slice(1));
  const prefixes = ['Mini', 'Mega', 'Old', 'Baby', 'Captain', 'Doctor', 'Super', 'Little'];
  const units = [];
  const seed = hash(use.join('-'));
  for (const c of caps) units.push(c);
  for (let i = 0; units.length < 8; i++) units.push(prefixes[(seed + i) % prefixes.length] + ' ' + caps[i % caps.length]);
  return {
    title: titleCase(use),
    board: 'Top ' + caps[0].toLowerCase() + 's',
    units: [...new Set(units)].slice(0, 8),
    verbs: GENERIC.verbs,
    endings: GENERIC.endings,
    tiles: GENERIC.tiles,
    rare: GENERIC.rare,
    sim: { label: use[0] + 's', start: 8, growth: 30, cap: 500 },
  };
}

function fillTheme(p) {
  const t = Object.assign({}, GENERIC, p);
  if (!t.board) t.board = t.title + ' leaderboard';
  if (!t.sim) t.sim = { label: t.title.toLowerCase() + 's', start: 8, growth: 30, cap: 500 };
  return t;
}

/**
 * Work out what a file name is about.
 * Returns { archetype, theme, confident, matched: [...], tokens }.
 */
function analyze(fileName) {
  const base = path.basename(fileName);
  const dot = base.lastIndexOf('.');
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const tokens = tokenize(stem);
  const matched = [];
  let packKey = null;
  let archeKey = null;

  const consider = (hit, token) => {
    if (!hit) return;
    if (hit.pack && !packKey) packKey = hit.pack;
    if (hit.arche && !archeKey) archeKey = hit.arche;
    matched.push({ token, word: hit.word, how: hit.how, pack: hit.pack, arche: hit.arche });
  };

  for (const t of tokens) {
    if (STOP.has(t)) continue;
    consider(lookup(t), t);
  }
  // Run-together names like "minecraftserver": look for known words inside.
  if (!packKey && !archeKey) {
    const compact = tokens.join('');
    for (const w of ALL_WORDS) {
      if (w.length >= 5 && compact.includes(w)) { consider({ word: w, pack: WORD_PACK.get(w), arche: WORD_ARCHE.get(w), how: 'inside' }, compact); break; }
    }
  }
  // Two glued words like "ur_mom" are handled by tokens; a lone pair like "yomama" by lookup above.

  const confident = !!(packKey || archeKey);
  let theme;
  if (packKey) theme = fillTheme(PACKS[packKey]);
  else if (archeKey) {
    const extra = tokens.filter((t) => !STOP.has(t) && !WORD_ARCHE.has(t));
    const own = tokens.filter((t) => !STOP.has(t));
    theme = extra.length ? fillTheme(deriveTheme(extra)) : fillTheme(Object.assign({}, PACKS.fantasy, { title: titleCase(own.length ? own : ['sample']) }));
  } else theme = fillTheme(deriveTheme(tokens));

  let archetype = archeKey;
  if (!archetype && packKey) archetype = PACKS[packKey].arche[0];
  if (!archetype) {
    const options = ['battle', 'worldmap', 'records', 'sim', 'textgen', 'plot'];
    archetype = options[hash(stem.toLowerCase()) % options.length];
  }
  // A pack that needs special handling wins over a generic shape word.
  if (packKey && PACKS[packKey].pairs && archetype !== 'textgen') archetype = 'textgen';
  if (archetype === 'textgen' && !theme.pairs && (!theme.units || !theme.units.length)) theme = fillTheme(deriveTheme(tokens));

  return { archetype, theme, packKey, confident, matched, tokens, stem };
}

function curveFor(tokens, stem) {
  const t = tokens.join(' ');
  if (/\b(saw|sawtooth)\b/.test(t)) return 'saw';
  if (/\b(parabola|bowl|curve|quadratic)\b/.test(t)) return 'bowl';
  if (/\b(step|steps|stair|stairs|staircase)\b/.test(t)) return 'steps';
  if (/\b(wave|sine|sin|sound|audio)\b/.test(t)) return 'wave';
  return ['wave', 'saw', 'bowl', 'steps'][hash(stem) % 4];
}

function normalizeExt(ext) {
  ext = (ext || '').toLowerCase();
  return EXT_ALIASES[ext] || ext;
}

function classIdFor(stem, tokens) {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(stem)) return stem;
  const pascal = tokens.map((w) => w[0].toUpperCase() + w.slice(1)).join('') || 'Main';
  return /^\d/.test(pascal) ? 'X' + pascal : pascal;
}

/**
 * Generate source code for fileName.
 * Returns { code, analysis } or null when this language is not supported
 * (or the name asks for something this generator hands to another template).
 */
function generate(fileName) {
  const base = path.basename(fileName);
  const dot = base.lastIndexOf('.');
  const ext = normalizeExt(dot > 0 ? base.slice(dot + 1) : '');
  if (!SUPPORTED.includes(ext)) return null;

  const analysis = analyze(fileName);
  if (analysis.archetype === 'vault') return { code: null, analysis };

  const ctx = {
    file: base,
    classId: classIdFor(analysis.stem, analysis.tokens),
    seed: 1000 + (hash(base.toLowerCase()) % 60000),
    curve: curveFor(analysis.tokens, analysis.stem),
  };
  const build = A[analysis.archetype];
  if (!build) return null;
  const program = build(analysis.theme, ctx);
  const code = emit(ext, program, ctx);
  return code ? { code, analysis } : null;
}

module.exports = { analyze, generate, SUPPORTED, normalizeExt };

};
__mods["lib/ai/ir.js"] = function (module, exports, require) {
'use strict';
// Tiny language-neutral program representation. Programs built with these
// helpers are compiled to many languages by emit.js.
//
// Everything is an integer, plus constant string arrays for text. That keeps
// the output identical across languages, so every compiled version can be
// tested against the others.

const X = (a) => (typeof a === 'number' ? { k: 'lit', v: a } : typeof a === 'string' ? { k: 'var', n: a } : a);
const bin = (op) => (a, b) => ({ k: 'bin', op, a: X(a), b: X(b) });

module.exports = {
  lit: (n) => ({ k: 'lit', v: n }),
  v: (n) => ({ k: 'var', n }),
  idx: (arr, i) => ({ k: 'idx', arr, i: X(i) }),
  len: (arr) => ({ k: 'len', arr }),
  call: (f, ...args) => ({ k: 'call', f, args: args.map(X) }),
  add: bin('+'), sub: bin('-'), mul: bin('*'), idiv: bin('/'), mod: bin('%'),
  lt: bin('<'), gt: bin('>'), le: bin('<='), ge: bin('>='), eq: bin('=='), ne: bin('!='),
  and: bin('&&'), or: bin('||'),

  decl: (n, e) => ({ k: 'decl', n, e: X(e) }),
  set: (n, e) => ({ k: 'set', n, e: X(e) }),
  setIdx: (arr, i, e) => ({ k: 'setIdx', arr, i: X(i), e: X(e) }),
  If: (c, t, f = []) => ({ k: 'if', c, t, f }),
  For: (n, from, to, body) => ({ k: 'for', n, from: X(from), to: X(to), body }),
  While: (c, body) => ({ k: 'while', c, body }),
  ret: (e) => ({ k: 'ret', e: X(e) }),
  run: (callNode) => ({ k: 'run', e: callNode }),
  // out / outln take text (strings) and expressions (numbers or nodes)
  out: (...parts) => ({ k: 'out', nl: false, parts: parts.map((p) => (typeof p === 'string' ? { k: 'txt', s: p } : X(p))) }),
  outln: (...parts) => ({ k: 'out', nl: true, parts: parts.map((p) => (typeof p === 'string' ? { k: 'txt', s: p } : X(p))) }),
};

};
__mods["lib/ai/archetypes.js"] = function (module, exports, require) {
'use strict';
// Program shapes. Each takes a theme (vocabulary) and returns an IR program.
//
// Rules that keep the compiled output valid in every language:
//   * never nest one call inside another call's arguments (Rust borrow rules)
//   * never put a call inside an out/outln part
//   * give every local in a function a unique name (Java/C# forbid shadowing)

const { v, idx, len, call, add, sub, mul, idiv, mod, lt, gt, ge, eq, ne, and, or,
  decl, set, setIdx, If, For, While, ret, run, out, outln } = require('./ir');

const RND = {
  name: 'rnd',
  params: ['n'],
  body: [
    set('seed', mod(add(mul('seed', 75), 74), 65537)),
    ret(mod(add('seed', idiv('seed', 256)), 'n')),
  ],
};

const zeros = (n) => Array.from({ length: n }, () => 0);
const take = (list, n) => list.slice(0, n);

// ---------------------------------------------------------------- battle
function battle(T, ctx) {
  return {
    title: T.title + ' arena',
    strs: { NAMES: take(T.units, 6), MOVES: take(T.verbs, 6) },
    state: { seed: ctx.seed },
    marrs: { hp: [0, 0], fighter: [0, 0] },
    funcs: [
      RND,
      {
        name: 'strike',
        params: ['src', 'tgt'],
        body: [
          decl('dmg', add(3, call('rnd', 8))),
          decl('mv', call('rnd', len('MOVES'))),
          setIdx('hp', 'tgt', sub(idx('hp', 'tgt'), 'dmg')),
          If(lt(idx('hp', 'tgt'), 0), [setIdx('hp', 'tgt', 0)]),
          outln(idx('NAMES', idx('fighter', 'src')), ' ', idx('MOVES', 'mv'), ' ', idx('NAMES', idx('fighter', 'tgt')),
            ' for ', v('dmg'), ' damage (', idx('hp', 'tgt'), ' hp left)'),
        ],
      },
    ],
    main: [
      decl('a', call('rnd', len('NAMES'))),
      decl('b', call('rnd', sub(len('NAMES'), 1))),
      If(ge('b', 'a'), [set('b', add('b', 1))]),
      setIdx('fighter', 0, 'a'),
      setIdx('fighter', 1, 'b'),
      decl('hp0', call('rnd', 20)),
      decl('hp1', call('rnd', 20)),
      setIdx('hp', 0, add(30, 'hp0')),
      setIdx('hp', 1, add(30, 'hp1')),
      outln('== ', T.title, ' arena: ', idx('NAMES', 'a'), ' vs ', idx('NAMES', 'b'), ' =='),
      decl('turn', 1),
      While(and(gt(idx('hp', 0), 0), gt(idx('hp', 1), 0)), [
        decl('src', call('rnd', 2)),
        run(call('strike', 'src', sub(1, 'src'))),
        set('turn', add('turn', 1)),
      ]),
      If(gt(idx('hp', 0), 0),
        [outln(idx('NAMES', idx('fighter', 0)), ' wins after ', v('turn'), ' turns!')],
        [outln(idx('NAMES', idx('fighter', 1)), ' wins after ', v('turn'), ' turns!')]),
    ],
  };
}

// ---------------------------------------------------------------- worldmap
function worldmap(T, ctx) {
  const W = 48;
  const H = 16;
  const tiles = T.tiles.map((t) => t[0]).concat([T.rare[0]]);
  const names = T.tiles.map((t) => t[1]).concat([T.rare[1]]);
  return {
    title: T.title + ' terrain generator',
    strs: { TILES: tiles, TILE_NAMES: names },
    state: { seed: ctx.seed },
    marrs: { grid: zeros(W * H), cnt: zeros(6) },
    funcs: [
      RND,
      {
        name: 'height',
        params: ['x', 'y'],
        body: [
          decl('lvl', add(add(mod(mul('x', 7), 11), mod(add(mul('y', 13), mul('x', 3)), 11)), mod(mul('x', 'y'), 5))),
          decl('noise', call('rnd', 4)),
          ret(add('lvl', 'noise')),
        ],
      },
      {
        name: 'tile_for',
        params: ['h'],
        body: [
          If(lt('h', 7), [ret(0)]),
          If(lt('h', 11), [ret(1)]),
          If(lt('h', 16), [ret(2)]),
          If(lt('h', 21), [ret(3)]),
          ret(4),
        ],
      },
    ],
    main: [
      outln('== ', T.title, ' terrain =='),
      For('y', 0, H, [
        For('x', 0, W, [
          decl('h', call('height', 'x', 'y')),
          decl('t', call('tile_for', 'h')),
          decl('lucky', call('rnd', 60)),
          If(eq('lucky', 0), [set('t', 5)]),
          setIdx('grid', add(mul('y', W), 'x'), 't'),
          setIdx('cnt', 't', add(idx('cnt', 't'), 1)),
          out(idx('TILES', 't')),
        ]),
        outln(),
      ]),
      outln(),
      For('k', 0, len('TILE_NAMES'), [
        outln(idx('TILES', 'k'), '  ', idx('TILE_NAMES', 'k'), ': ', idx('cnt', 'k')),
      ]),
    ],
  };
}

// ---------------------------------------------------------------- textgen
function textgen(T, ctx) {
  const lines = 8;
  if (T.pairs) {
    const P = T.pairs;
    return {
      title: T.title + ' line generator',
      strs: { A: P.map((p) => p[0]), B: P.map((p) => p[1]) },
      state: { seed: ctx.seed },
      marrs: {},
      funcs: [RND],
      main: [
        outln('== ', T.title, ' =='),
        For('n', 0, lines, [
          decl('i', call('rnd', len('A'))),
          outln(add('n', 1), '. ', T.prefix, idx('A', 'i'), T.mid, idx('B', 'i'), T.suffix),
        ]),
      ],
    };
  }
  return {
    title: T.title + ' line generator',
    strs: { UNITS: T.units, VERBS: T.verbs, ENDINGS: T.endings },
    state: { seed: ctx.seed },
    marrs: {},
    funcs: [RND],
    main: [
      outln('== ', T.title, ' =='),
      For('n', 0, lines, [
        decl('i', call('rnd', len('UNITS'))),
        decl('j', call('rnd', len('VERBS'))),
        decl('k', call('rnd', len('UNITS'))),
        decl('m', call('rnd', len('ENDINGS'))),
        If(eq('k', 'i'), [set('k', mod(add('k', 1), len('UNITS')))]),
        outln(add('n', 1), '. ', idx('UNITS', 'i'), ' ', idx('VERBS', 'j'), ' ', idx('UNITS', 'k'), ' ', idx('ENDINGS', 'm')),
      ]),
    ],
  };
}

// ---------------------------------------------------------------- records (leaderboard + sort)
function records(T, ctx) {
  const N = 8;
  return {
    title: T.title + ' leaderboard',
    strs: { NAMES: take(T.units, N) },
    state: { seed: ctx.seed },
    marrs: { score: zeros(N), order: zeros(N) },
    funcs: [RND],
    main: [
      outln('== ', T.board, ' =='),
      For('i', 0, N, [
        decl('s', call('rnd', 900)),
        setIdx('score', 'i', add(100, 's')),
        setIdx('order', 'i', 'i'),
      ]),
      For('p', 0, N - 1, [
        For('q', 0, sub(N - 1, 'p'), [
          If(lt(idx('score', idx('order', 'q')), idx('score', idx('order', add('q', 1)))), [
            decl('tmp', idx('order', 'q')),
            setIdx('order', 'q', idx('order', add('q', 1))),
            setIdx('order', add('q', 1), 'tmp'),
          ]),
        ]),
      ]),
      For('r', 0, N, [
        outln(add('r', 1), '. ', idx('NAMES', idx('order', 'r')), ' - ', idx('score', idx('order', 'r'))),
      ]),
      decl('total', 0),
      For('u', 0, N, [set('total', add('total', idx('score', 'u')))]),
      outln(),
      outln('Total: ', v('total'), ' | Average: ', idiv('total', N), ' | Leader: ', idx('NAMES', idx('order', 0))),
    ],
  };
}

// ---------------------------------------------------------------- sim (logistic growth with noise)
function sim(T, ctx) {
  const S = T.sim;
  const scale = Math.max(1, Math.floor(S.cap / 40));
  return {
    title: S.label + ' population simulation',
    strs: {},
    state: { seed: ctx.seed, pop: S.start },
    marrs: {},
    funcs: [
      RND,
      {
        name: 'tick',
        params: [],
        body: [
          decl('gain', idiv(mul('pop', S.growth), 100)),
          decl('room', sub(S.cap, 'pop')),
          decl('delta', idiv(mul('gain', 'room'), S.cap)),
          decl('shock', call('rnd', 7)),
          set('pop', add('pop', sub(add('delta', 'shock'), 3))),
          If(lt('pop', 1), [set('pop', 1)]),
          If(gt('pop', S.cap), [set('pop', S.cap)]),
        ],
      },
    ],
    main: [
      outln('== ', S.label, ' over time =='),
      For('day', 0, 16, [
        out('day ', v('day'), ' | ', v('pop'), ' ', S.label, ' '),
        For('b', 0, idiv('pop', scale), [out('#')]),
        outln(),
        run(call('tick')),
      ]),
      outln('final ', S.label, ': ', v('pop')),
    ],
  };
}

// ---------------------------------------------------------------- plot (ASCII curve)
function plot(T, ctx) {
  const kind = ctx.curve;
  const W = 60;
  const R = 13;
  const bodies = {
    wave: [
      decl('p', mod('x', 24)),
      If(lt('p', 12), [ret('p')]),
      ret(sub(24, 'p')),
    ],
    saw: [ret(idiv(mul(mod('x', 20), 12), 19))],
    bowl: [
      decl('d', sub('x', 30)),
      decl('r', idiv(mul('d', 'd'), 75)),
      If(gt('r', 12), [ret(12)]),
      ret('r'),
    ],
    steps: [ret(mod(idiv('x', 5), 13))],
  };
  const labels = { wave: 'triangle wave', saw: 'sawtooth', bowl: 'parabola', steps: 'staircase' };
  return {
    title: T.title + ' plot (' + labels[kind] + ')',
    strs: {},
    state: { seed: ctx.seed },
    marrs: {},
    funcs: [
      RND,
      { name: 'curve', params: ['x'], body: bodies[kind] },
    ],
    main: [
      outln('== ', T.title, ': ', labels[kind], ' =='),
      For('r', 0, R, [
        decl('row', sub(R - 1, 'r')),
        For('c', 0, W, [
          decl('y', call('curve', 'c')),
          If(eq('y', 'row'), [out('*')], [out(' ')]),
        ]),
        outln(),
      ]),
      For('c2', 0, W, [out('-')]),
      outln(),
    ],
  };
}

// ---------------------------------------------------------------- mandel (fixed-point)
function mandel(T, ctx) {
  const MAXIT = 60;
  return {
    title: 'Mandelbrot set (fixed-point, ASCII)',
    strs: { SHADES: [' ', '.', ':', '-', '=', '+', '*', '#', '%', '@'] },
    state: { seed: ctx.seed },
    marrs: {},
    funcs: [
      {
        name: 'fmul',
        params: ['a', 'b'],
        body: [
          decl('p', mul('a', 'b')),
          If(lt('p', 0), [ret(sub(0, idiv(sub(0, 'p'), 1024)))]),
          ret(idiv('p', 1024)),
        ],
      },
      {
        name: 'escape_time',
        params: ['cr', 'ci'],
        body: [
          decl('zr', 0), decl('zi', 0), decl('n', 0), decl('sa', 0), decl('sb', 0),
          While(lt('n', MAXIT), [
            set('sa', call('fmul', 'zr', 'zr')),
            set('sb', call('fmul', 'zi', 'zi')),
            If(gt(add('sa', 'sb'), 4096), [ret('n')]),
            decl('t', add(sub('sa', 'sb'), 'cr')),
            decl('m', call('fmul', 'zr', 'zi')),
            set('zi', add(mul(2, 'm'), 'ci')),
            set('zr', 't'),
            set('n', add('n', 1)),
          ]),
          ret('n'),
        ],
      },
    ],
    main: [
      For('row', 0, 24, [
        For('col', 0, 80, [
          decl('cr', sub(idiv(mul('col', 1024), 25), 2252)),
          decl('ci', sub(idiv(mul('row', 1024), 9), 1365)),
          decl('n', call('escape_time', 'cr', 'ci')),
          decl('s', mod('n', 9)),
          If(eq('n', MAXIT), [set('s', 9)]),
          out(idx('SHADES', 's')),
        ]),
        outln(),
      ]),
    ],
  };
}

// ---------------------------------------------------------------- life
function life(T, ctx) {
  const W = 40;
  const H = 16;
  const idxOf = (y, x) => add(mul(y, W), x);
  return {
    title: "Conway's Game of Life",
    strs: { GLYPH: [' ', '#'] },
    state: { seed: ctx.seed },
    marrs: { cells: zeros(W * H), nxt: zeros(W * H) },
    funcs: [
      RND,
      {
        name: 'alive',
        params: ['x', 'y'],
        body: [
          decl('xx', mod(add('x', W), W)),
          decl('yy', mod(add('y', H), H)),
          ret(idx('cells', idxOf('yy', 'xx'))),
        ],
      },
      {
        name: 'neighbours',
        params: ['x', 'y'],
        body: [
          decl('c', 0),
          For('dy', -1, 2, [
            For('dx', -1, 2, [
              If(or(ne('dy', 0), ne('dx', 0)), [
                decl('ax', add('x', 'dx')),
                decl('ay', add('y', 'dy')),
                decl('a', call('alive', 'ax', 'ay')),
                set('c', add('c', 'a')),
              ]),
            ]),
          ]),
          ret('c'),
        ],
      },
      {
        name: 'step_world',
        params: [],
        body: [
          For('y', 0, H, [
            For('x', 0, W, [
              decl('n', call('neighbours', 'x', 'y')),
              decl('cur', idx('cells', idxOf('y', 'x'))),
              If(or(eq('n', 3), and(eq('cur', 1), eq('n', 2))),
                [setIdx('nxt', idxOf('y', 'x'), 1)],
                [setIdx('nxt', idxOf('y', 'x'), 0)]),
            ]),
          ]),
          For('k', 0, W * H, [setIdx('cells', 'k', idx('nxt', 'k'))]),
        ],
      },
    ],
    main: [
      For('i', 0, W * H, [
        decl('r', call('rnd', 4)),
        If(eq('r', 0), [setIdx('cells', 'i', 1)]),
      ]),
      For('g', 0, 6, [
        outln('generation ', v('g')),
        For('y', 0, H, [
          For('x', 0, W, [out(idx('GLYPH', idx('cells', idxOf('y', 'x'))))]),
          outln(),
        ]),
        run(call('step_world')),
      ]),
    ],
  };
}

module.exports = { battle, worldmap, textgen, records, sim, plot, mandel, life };

};
__mods["lib/ai/emit.js"] = function (module, exports, require) {
'use strict';
// Compiles an IR program (see ir.js) into source code for many languages.

const has = (o, k) => !!o && Object.prototype.hasOwnProperty.call(o, k);
const json = (s) => JSON.stringify(s);
const single = (s) => "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'";

function hasRet(list) {
  for (const s of list) {
    if (s.k === 'ret') return true;
    if (s.k === 'if' && (hasRet(s.t) || hasRet(s.f))) return true;
    if ((s.k === 'for' || s.k === 'while') && hasRet(s.body)) return true;
  }
  return false;
}

// Names of state variables / mutable arrays touched inside a statement list.
function usedGlobals(prog, list, onlyAssigned) {
  const found = new Set();
  const isG = (n) => has(prog.state, n) || has(prog.marrs, n);
  const ex = (e) => {
    if (!e) return;
    if (e.k === 'var' && !onlyAssigned && isG(e.n)) found.add(e.n);
    if (e.k === 'idx') { if (!onlyAssigned && has(prog.marrs, e.arr)) found.add(e.arr); ex(e.i); }
    if (e.k === 'bin') { ex(e.a); ex(e.b); }
    if (e.k === 'call') e.args.forEach(ex);
  };
  const walk = (l) => {
    for (const s of l) {
      if (s.k === 'decl') ex(s.e);
      else if (s.k === 'set') { if (has(prog.state, s.n)) found.add(s.n); ex(s.e); }
      else if (s.k === 'setIdx') { if (!onlyAssigned && has(prog.marrs, s.arr)) found.add(s.arr); ex(s.i); ex(s.e); }
      else if (s.k === 'if') { ex(s.c); walk(s.t); walk(s.f); }
      else if (s.k === 'for') { ex(s.from); ex(s.to); walk(s.body); }
      else if (s.k === 'while') { ex(s.c); walk(s.body); }
      else if (s.k === 'ret' || s.k === 'run') ex(s.e);
      else if (s.k === 'out') s.parts.forEach(ex);
    }
  };
  walk(list);
  return [...found];
}

const PREC = { '||': 1, '&&': 2, '==': 3, '!=': 3, '<': 4, '>': 4, '<=': 4, '>=': 4, '+': 5, '-': 5, '*': 6, '/': 6, '%': 6 };

class Lang {
  constructor(prog, ctx) {
    this.p = prog;
    this.c = ctx;
    this.lines = [];
    this.n = 0;
    this.inMain = false;
  }

  // ---- output helpers
  w(s = '') { this.lines.push(s === '' ? '' : '    '.repeat(this.n) + s); }
  ind(f) { this.n++; f(); this.n--; }
  block(list) {
    this.ind(() => {
      if (!list.length && this.EMPTY) this.w(this.EMPTY);
      else this.stmts(list);
    });
  }

  // ---- program facts
  isStr(e) { return e.k === 'idx' && has(this.p.strs, e.arr); }
  isState(n) { return has(this.p.state, n); }
  isMArr(n) { return has(this.p.marrs, n); }
  arrLen(a) {
    if (has(this.p.strs, a)) return this.p.strs[a].length;
    if (has(this.p.marrs, a)) return this.p.marrs[a].length;
    return this.p.ints[a].length;
  }
  parts(list, nl) {
    const out = [];
    const text = (s) => {
      if (!s) return;
      if (out.length && out[out.length - 1].text !== undefined) out[out.length - 1].text += s;
      else out.push({ text: s });
    };
    for (const p of list) { if (p.k === 'txt') text(p.s); else out.push({ e: p }); }
    if (nl) text('\n');
    return out;
  }
  // Splits a trailing newline off so languages with println can use it.
  lineParts(list, nl) {
    const parts = this.parts(list, nl);
    let newline = false;
    const last = parts[parts.length - 1];
    if (nl && last && last.text !== undefined && last.text.endsWith('\n')) {
      last.text = last.text.slice(0, -1);
      newline = true;
      if (!last.text) parts.pop();
    }
    return { parts, newline };
  }

  // ---- expressions
  // ex(e, true)            -> no outer parentheses (statement level, call arguments)
  // ex(e)                  -> always safe to embed anywhere (concatenation, casts)
  // ex(e, false, prec, side) -> parenthesised only where operator precedence needs it
  ex(e, top = false, parentPrec = 99, side = 'left', parentOp = '') {
    switch (e.k) {
      case 'lit': return e.v < 0 && !top ? '(' + e.v + ')' : String(e.v);
      case 'var': return this.ref(e.n);
      case 'idx': return this.idxRef(e.arr, e.i);
      case 'len': return String(this.arrLen(e.arr));
      case 'call': return this.callEx(e.f, e.args);
      case 'bin': {
        const p = PREC[e.op];
        const text = this.binEx(e.op, this.ex(e.a, false, p, 'left', e.op), this.ex(e.b, false, p, 'right', e.op));
        if (top || this.atomic(e.op)) return text;
        const mixed = parentOp === '||' && e.op === '&&';
        return p < parentPrec || (p === parentPrec && side === 'right') || mixed ? '(' + text + ')' : text;
      }
      default: throw new Error('bad expr ' + e.k);
    }
  }
  atomic() { return false; }
  ref(n) { return n; }
  idxRef(arr, i) { return arr + '[' + this.ex(i, true) + ']'; }
  callEx(f, args) { return f + '(' + args.map((a) => this.ex(a, true)).join(', ') + ')'; }
  binEx(op, a, b) {
    const map = { '/': this.IDIV || '/' };
    return a + ' ' + (map[op] || op) + ' ' + b;
  }

  // ---- statements
  stmts(list) { for (const s of list) this.st(s); }
  st(s) {
    switch (s.k) {
      case 'decl': this.w(this.declS(s.n, this.ex(s.e, true))); break;
      case 'set': this.w(this.setS(s.n, this.ex(s.e, true))); break;
      case 'setIdx': this.w(this.setIdxS(s.arr, this.ex(s.i, true), this.ex(s.e, true))); break;
      case 'if': this.ifS(s); break;
      case 'for': this.forS(s); break;
      case 'while': this.whileS(s); break;
      case 'ret': this.w(this.retS(this.ex(s.e, true))); break;
      case 'run': this.w(this.runS(this.ex(s.e, true))); break;
      case 'out': this.w(this.printS(s.parts, s.nl)); break;
      default: throw new Error('bad stmt ' + s.k);
    }
  }
  ifS(s) {
    this.w(this.ifOpen(this.ex(s.c, true)));
    this.block(s.t);
    if (s.f.length) {
      this.w(this.elseOpen());
      this.block(s.f);
    }
    const c = this.close();
    if (c) this.w(c);
  }
  whileS(s) {
    this.w(this.whileOpen(this.ex(s.c, true)));
    this.block(s.body);
    const c = this.close();
    if (c) this.w(c);
  }
  forS(s) {
    this.w(this.forOpen(s.n, s.from, s.to));
    this.block(s.body);
    const c = this.close();
    if (c) this.w(c);
  }
}

// ======================================================================
// Brace languages share most of their shape.
class Brace extends Lang {
  close() { return '}'; }
  ifOpen(c) { return 'if (' + c + ') {'; }
  elseOpen() { return '} else {'; }
  whileOpen(c) { return 'while (' + c + ') {'; }
  declS(n, e) { return this.TYPE + ' ' + n + ' = ' + e + ';'; }
  setS(n, e) { return this.ref(n) + ' = ' + e + ';'; }
  setIdxS(arr, i, e) { return this.idxRef(arr, { _s: i }) + ' = ' + e + ';'; }
  retS(e) { return 'return ' + e + ';'; }
  runS(e) { return e + ';'; }
  forOpen(n, from, to) {
    return 'for (' + this.TYPE + ' ' + n + ' = ' + this.ex(from, true) + '; ' + n + ' < ' + this.ex(to, true) + '; ' + n + '++) {';
  }
  idxRef(arr, i) { return arr + '[' + (i && i._s !== undefined ? i._s : this.ex(i, true)) + ']'; }
  hasR(f) { return hasRet(f.body); }
  program() {
    this.header();
    this.globals();
    for (const f of this.p.funcs) this.func(f);
    this.mainFn();
    this.footer();
    return this.lines.join('\n') + '\n';
  }
  func(f) {
    this.w(this.funcSig(f, this.hasR(f)));
    this.ind(() => { this.funcPrelude(f); this.stmts(f.body); });
    this.w('}');
    this.w();
  }
  funcPrelude() {}
  footer() {}
}

// ---------------------------------------------------------------- C / C++
class C extends Brace {
  constructor(p, c, cpp) { super(p, c); this.TYPE = 'int'; this.cpp = cpp; }
  header() {
    this.w('// ' + this.c.file + ': ' + this.p.title);
    this.w(this.cpp ? '#include <cstdio>' : '#include <stdio.h>');
    this.w();
  }
  globals() {
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('static const char *' + k + '[] = {' + v.map(json).join(', ') + '};');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('static const int ' + k + '[] = {' + v.join(', ') + '};');
    for (const [k, v] of Object.entries(this.p.state || {})) this.w('static int ' + k + ' = ' + v + ';');
    for (const [k, v] of Object.entries(this.p.marrs || {})) {
      this.w(v.every((x) => x === 0) ? 'static int ' + k + '[' + v.length + '];' : 'static int ' + k + '[] = {' + v.join(', ') + '};');
    }
    this.w();
  }
  funcSig(f, ret) { return 'static ' + (ret ? 'int' : 'void') + ' ' + f.name + '(' + (f.params.length ? f.params.map((p) => 'int ' + p).join(', ') : 'void') + ') {'; }
  mainFn() {
    this.w('int main(void) {');
    this.ind(() => { this.stmts(this.p.main); this.w('return 0;'); });
    this.w('}');
  }
  printS(parts, nl) {
    let fmt = '';
    const args = [];
    for (const p of this.parts(parts, nl)) {
      if (p.text !== undefined) fmt += json(p.text).slice(1, -1).replace(/%/g, '%%');
      else { fmt += this.isStr(p.e) ? '%s' : '%d'; args.push(this.ex(p.e, true)); }
    }
    return 'printf("' + fmt + '"' + (args.length ? ', ' + args.join(', ') : '') + ');';
  }
}

// ---------------------------------------------------------------- Java
class Java extends Brace {
  constructor(p, c) { super(p, c); this.TYPE = 'int'; }
  header() {
    this.w('// ' + this.c.file + ': ' + this.p.title);
    this.w('public class ' + this.c.classId + ' {');
    this.n = 1;
  }
  globals() {
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('static final String[] ' + k + ' = {' + v.map(json).join(', ') + '};');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('static final int[] ' + k + ' = {' + v.join(', ') + '};');
    for (const [k, v] of Object.entries(this.p.state || {})) this.w('static int ' + k + ' = ' + v + ';');
    for (const [k, v] of Object.entries(this.p.marrs || {})) {
      this.w(v.every((x) => x === 0) ? 'static int[] ' + k + ' = new int[' + v.length + '];' : 'static int[] ' + k + ' = {' + v.join(', ') + '};');
    }
    this.w();
  }
  funcSig(f, ret) { return 'static ' + (ret ? 'int' : 'void') + ' ' + f.name + '(' + f.params.map((p) => 'int ' + p).join(', ') + ') {'; }
  mainFn() {
    this.w('public static void main(String[] args) {');
    this.ind(() => this.stmts(this.p.main));
    this.w('}');
  }
  footer() { this.n = 0; this.w('}'); }
  printS(parts, nl) {
    const { parts: ps, newline } = this.lineParts(parts, nl);
    const items = ps.map((p) => (p.text !== undefined ? json(p.text) : this.ex(p.e, false)));
    if (!items.length) return newline ? 'System.out.println();' : '';
    if (!ps[0].text && ps[0].text !== '') items.unshift('""');
    return 'System.out.' + (newline ? 'println' : 'print') + '(' + items.join(' + ') + ');';
  }
}

// ---------------------------------------------------------------- C#
class CSharp extends Brace {
  constructor(p, c) { super(p, c); this.TYPE = 'int'; }
  header() {
    this.w('// ' + this.c.file + ': ' + this.p.title);
    this.w('using System;');
    this.w();
    this.w('internal static class Program {');
    this.n = 1;
  }
  globals() {
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('static readonly string[] ' + k + ' = {' + v.map(json).join(', ') + '};');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('static readonly int[] ' + k + ' = {' + v.join(', ') + '};');
    for (const [k, v] of Object.entries(this.p.state || {})) this.w('static int ' + k + ' = ' + v + ';');
    for (const [k, v] of Object.entries(this.p.marrs || {})) {
      this.w(v.every((x) => x === 0) ? 'static int[] ' + k + ' = new int[' + v.length + '];' : 'static int[] ' + k + ' = {' + v.join(', ') + '};');
    }
    this.w();
  }
  funcSig(f, ret) { return 'static ' + (ret ? 'int' : 'void') + ' ' + f.name + '(' + f.params.map((p) => 'int ' + p).join(', ') + ') {'; }
  mainFn() {
    this.w('static void Main() {');
    this.ind(() => this.stmts(this.p.main));
    this.w('}');
  }
  footer() { this.n = 0; this.w('}'); }
  printS(parts, nl) {
    const { parts: ps, newline } = this.lineParts(parts, nl);
    const items = ps.map((p) => (p.text !== undefined ? json(p.text) : this.ex(p.e, false)));
    if (!items.length) return newline ? 'Console.WriteLine();' : '';
    if (ps[0].text === undefined) items.unshift('""');
    return 'Console.' + (newline ? 'WriteLine' : 'Write') + '(' + items.join(' + ') + ');';
  }
}

// ---------------------------------------------------------------- JavaScript / TypeScript
class JS extends Brace {
  constructor(p, c, ts) { super(p, c); this.ts = ts; this.IDIV = null; }
  header() {
    this.w('// ' + this.c.file + ': ' + this.p.title);
    if (this.ts) this.w('declare const process: { stdout: { write(text: string): void } };');
    else this.w("'use strict';");
    this.w();
  }
  globals() {
    const T = this.ts;
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('const ' + k + (T ? ': string[]' : '') + ' = [' + v.map(single).join(', ') + '];');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('const ' + k + (T ? ': number[]' : '') + ' = [' + v.join(', ') + '];');
    for (const [k, v] of Object.entries(this.p.state || {})) this.w('let ' + k + (T ? ': number' : '') + ' = ' + v + ';');
    for (const [k, v] of Object.entries(this.p.marrs || {})) {
      const init = v.every((x) => x === 0) ? 'new Array(' + v.length + ').fill(0)' : '[' + v.join(', ') + ']';
      this.w('const ' + k + (T ? ': number[]' : '') + ' = ' + init + ';');
    }
    this.w();
  }
  declS(n, e) { return 'let ' + n + (this.ts ? ': number' : '') + ' = ' + e + ';'; }
  forOpen(n, from, to) {
    return 'for (let ' + n + ' = ' + this.ex(from, true) + '; ' + n + ' < ' + this.ex(to, true) + '; ' + n + '++) {';
  }
  atomic(op) { return op === '/'; }
  binEx(op, a, b) {
    if (op === '/') return 'Math.floor(' + a + ' / ' + b + ')';
    return a + ' ' + op + ' ' + b;
  }
  funcSig(f, ret) {
    if (!this.ts) return 'function ' + f.name + '(' + f.params.join(', ') + ') {';
    return 'function ' + f.name + '(' + f.params.map((p) => p + ': number').join(', ') + '): ' + (ret ? 'number' : 'void') + ' {';
  }
  mainFn() {
    this.w('function main()' + (this.ts ? ': void' : '') + ' {');
    this.ind(() => this.stmts(this.p.main));
    this.w('}');
    this.w();
  }
  footer() { this.w('main();'); }
  printS(parts, nl) {
    const { parts: ps, newline } = this.lineParts(parts, nl);
    const items = ps.map((p) => (p.text !== undefined ? single(p.text) : this.ex(p.e, false)));
    if (!items.length) return newline ? 'console.log();' : '';
    if (ps[0].text === undefined) items.unshift("''");
    const body = items.join(' + ');
    return newline ? 'console.log(' + body + ');' : 'process.stdout.write(' + body + ');';
  }
}

// ---------------------------------------------------------------- Go
class Go extends Brace {
  constructor(p, c) { super(p, c); }
  header() {
    this.w('// ' + this.c.file + ': ' + this.p.title);
    this.w('package main');
    this.w();
    this.w('import "fmt"');
    this.w();
  }
  globals() {
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('var ' + k + ' = []string{' + v.map(json).join(', ') + '}');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('var ' + k + ' = []int{' + v.join(', ') + '}');
    for (const [k, v] of Object.entries(this.p.state || {})) this.w('var ' + k + ' = ' + v);
    for (const [k, v] of Object.entries(this.p.marrs || {})) {
      this.w(v.every((x) => x === 0) ? 'var ' + k + ' = make([]int, ' + v.length + ')' : 'var ' + k + ' = []int{' + v.join(', ') + '}');
    }
    this.w();
  }
  ifOpen(c) { return 'if ' + c + ' {'; }
  whileOpen(c) { return 'for ' + c + ' {'; }
  declS(n, e) { return n + ' := ' + e; }
  setS(n, e) { return n + ' = ' + e; }
  setIdxS(arr, i, e) { return arr + '[' + i + '] = ' + e; }
  retS(e) { return 'return ' + e; }
  runS(e) { return e; }
  forOpen(n, from, to) { return 'for ' + n + ' := ' + this.ex(from, true) + '; ' + n + ' < ' + this.ex(to, true) + '; ' + n + '++ {'; }
  funcSig(f, ret) { return 'func ' + f.name + '(' + f.params.map((p) => p + ' int').join(', ') + ')' + (ret ? ' int' : '') + ' {'; }
  mainFn() {
    this.w('func main() {');
    this.ind(() => this.stmts(this.p.main));
    this.w('}');
  }
  printS(parts, nl) {
    let fmt = '';
    const args = [];
    for (const p of this.parts(parts, nl)) {
      if (p.text !== undefined) fmt += json(p.text).slice(1, -1).replace(/%/g, '%%');
      else { fmt += this.isStr(p.e) ? '%s' : '%d'; args.push(this.ex(p.e, true)); }
    }
    return 'fmt.Printf("' + fmt + '"' + (args.length ? ', ' + args.join(', ') : '') + ')';
  }
}

// ---------------------------------------------------------------- Rust
class Rust extends Brace {
  header() {
    this.w('// ' + this.c.file + ': ' + this.p.title);
    this.w('#![allow(dead_code, unused_variables, unused_mut, unused_assignments)]');
    this.w();
  }
  globals() {
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('const ' + k + ': [&str; ' + v.length + '] = [' + v.map(json).join(', ') + '];');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('const ' + k + ': [i32; ' + v.length + '] = [' + v.join(', ') + '];');
    this.w();
    this.w('struct State {');
    this.ind(() => {
      for (const k of Object.keys(this.p.state || {})) this.w(k + ': i32,');
      for (const [k, v] of Object.entries(this.p.marrs || {})) this.w(k + ': [i32; ' + v.length + '],');
    });
    this.w('}');
    this.w();
  }
  ref(n) { return this.isState(n) ? 'st.' + n : n; }
  idxRef(arr, i) {
    const raw = i && i._s !== undefined ? i._s : this.ex(i, false);
    const base = this.isMArr(arr) ? 'st.' + arr : arr;
    return base + '[' + raw + ' as usize]';
  }
  setIdxS(arr, i, e) { return (this.isMArr(arr) ? 'st.' + arr : arr) + '[(' + i + ') as usize] = ' + e + ';'; }
  callEx(f, args) { return f + '(' + [this.inMain ? '&mut st' : 'st'].concat(args.map((a) => this.ex(a, true))).join(', ') + ')'; }
  declS(n, e) { return 'let mut ' + n + ' = ' + e + ';'; }
  ifOpen(c) { return 'if ' + c + ' {'; }
  whileOpen(c) { return 'while ' + c + ' {'; }
  forOpen(n, from, to) { return 'for ' + n + ' in ' + this.ex(from, true) + '..' + this.ex(to, true) + ' {'; }
  funcSig(f, ret) {
    return 'fn ' + f.name + '(' + ['st: &mut State'].concat(f.params.map((p) => p + ': i32')).join(', ') + ')' + (ret ? ' -> i32' : '') + ' {';
  }
  mainFn() {
    this.w('fn main() {');
    this.ind(() => {
      this.inMain = true;
      const init = [];
      for (const [k, v] of Object.entries(this.p.state || {})) init.push(k + ': ' + v);
      for (const [k, v] of Object.entries(this.p.marrs || {})) init.push(k + ': ' + (v.every((x) => x === 0) ? '[0; ' + v.length + ']' : '[' + v.join(', ') + ']'));
      this.w('let mut st = State {');
      this.ind(() => init.forEach((s) => this.w(s + ',')));
      this.w('};');
      this.stmts(this.p.main);
      this.inMain = false;
    });
    this.w('}');
  }
  printS(parts, nl) {
    const { parts: ps, newline } = this.lineParts(parts, nl);
    let fmt = '';
    const args = [];
    for (const p of ps) {
      if (p.text !== undefined) fmt += json(p.text).slice(1, -1).replace(/\{/g, '{{').replace(/\}/g, '}}');
      else { fmt += '{}'; args.push(this.ex(p.e, true)); }
    }
    const mac = newline ? 'println!' : 'print!';
    if (!fmt && !args.length) return newline ? 'println!();' : '';
    return mac + '("' + fmt + '"' + (args.length ? ', ' + args.join(', ') : '') + ');';
  }
}

// ---------------------------------------------------------------- PHP
class PHP extends Brace {
  header() {
    this.w('<?php');
    this.w('// ' + this.c.file + ': ' + this.p.title);
    this.w('declare(strict_types=1);');
    this.w();
  }
  globals() {
    for (const [k, v] of Object.entries(this.p.strs || {})) this.w('const ' + k + ' = [' + v.map(single).join(', ') + '];');
    for (const [k, v] of Object.entries(this.p.ints || {})) this.w('const ' + k + ' = [' + v.join(', ') + '];');
    for (const [k, v] of Object.entries(this.p.state || {})) this.w('$' + k + ' = ' + v + ';');
    for (const [k, v] of Object.entries(this.p.marrs || {})) {
      this.w('$' + k + ' = ' + (v.every((x) => x === 0) ? 'array_fill(0, ' + v.length + ', 0)' : '[' + v.join(', ') + ']') + ';');
    }
    this.w();
  }
  ref(n) { return '$' + n; }
  idxRef(arr, i) {
    const raw = i && i._s !== undefined ? i._s : this.ex(i, true);
    return (has(this.p.strs, arr) || has(this.p.ints, arr) ? arr : '$' + arr) + '[' + raw + ']';
  }
  setIdxS(arr, i, e) { return '$' + arr + '[' + i + '] = ' + e + ';'; }
  declS(n, e) { return '$' + n + ' = ' + e + ';'; }
  setS(n, e) { return '$' + n + ' = ' + e + ';'; }
  atomic(op) { return op === '/'; }
  binEx(op, a, b) { return op === '/' ? 'intdiv(' + a + ', ' + b + ')' : a + ' ' + op + ' ' + b; }
  forOpen(n, from, to) { return 'for ($' + n + ' = ' + this.ex(from, true) + '; $' + n + ' < ' + this.ex(to, true) + '; $' + n + '++) {'; }
  funcSig(f, ret) { return 'function ' + f.name + '(' + f.params.map((p) => 'int $' + p).join(', ') + '): ' + (ret ? 'int' : 'void') + ' {'; }
  funcPrelude(f) {
    const g = usedGlobals(this.p, f.body, false);
    if (g.length) this.w('global ' + g.map((n) => '$' + n).join(', ') + ';');
  }
  mainFn() {
    this.w('function main(): void {');
    this.ind(() => {
      const g = usedGlobals(this.p, this.p.main, false);
      if (g.length) this.w('global ' + g.map((n) => '$' + n).join(', ') + ';');
      this.stmts(this.p.main);
    });
    this.w('}');
    this.w();
  }
  footer() { this.w('main();'); }
  printS(parts, nl) {
    const { parts: ps, newline } = this.lineParts(parts, nl);
    const items = ps.map((p) => (p.text !== undefined ? single(p.text) : this.ex(p.e, false)));
    if (newline) items.push('"\\n"');
    return items.length ? 'echo ' + items.join(', ') + ';' : '';
  }
}

// ======================================================================
// Indentation / keyword languages

class Python extends Lang {
  constructor(p, c) { super(p, c); this.EMPTY = 'pass'; this.IDIV = '//'; }
  close() { return null; }
  ifOpen(c) { return 'if ' + c + ':'; }
  elseOpen() { return 'else:'; }
  whileOpen(c) { return 'while ' + c + ':'; }
  forOpen(n, from, to) { return 'for ' + n + ' in range(' + this.ex(from, true) + ', ' + this.ex(to, true) + '):'; }
  binEx(op, a, b) {
    const m = { '/': '//', '&&': 'and', '||': 'or' };
    return a + ' ' + (m[op] || op) + ' ' + b;
  }
  declS(n, e) { return n + ' = ' + e; }
  setS(n, e) { return n + ' = ' + e; }
  setIdxS(arr, i, e) { return arr + '[' + i + '] = ' + e; }
  retS(e) { return 'return ' + e; }
  runS(e) { return e; }
  printS(parts, nl) {
    const items = this.parts(parts, false).map((p) => (p.text !== undefined ? json(p.text) : this.ex(p.e, true)));
    if (!items.length) return nl ? 'print()' : '';
    return 'print(' + items.join(', ') + ', sep=""' + (nl ? '' : ', end=""') + ')';
  }
  program() {
    const p = this.p;
    this.w('# ' + this.c.file + ': ' + p.title);
    this.w();
    for (const [k, v] of Object.entries(p.strs || {})) this.w(k + ' = [' + v.map(json).join(', ') + ']');
    for (const [k, v] of Object.entries(p.ints || {})) this.w(k + ' = [' + v.join(', ') + ']');
    for (const [k, v] of Object.entries(p.state || {})) this.w(k + ' = ' + v);
    for (const [k, v] of Object.entries(p.marrs || {})) this.w(k + ' = ' + (v.every((x) => x === 0) ? '[0] * ' + v.length : '[' + v.join(', ') + ']'));
    this.w();
    this.w();
    const fn = (name, params, body) => {
      this.w('def ' + name + '(' + params.join(', ') + '):');
      this.ind(() => {
        const g = usedGlobals(p, body, true);
        if (g.length) this.w('global ' + g.join(', '));
        if (!body.length) this.w('pass'); else this.stmts(body);
      });
      this.w();
      this.w();
    };
    for (const f of p.funcs) fn(f.name, f.params, f.body);
    fn('main', [], p.main);
    this.w('if __name__ == "__main__":');
    this.ind(() => this.w('main()'));
    return this.lines.join('\n') + '\n';
  }
}

class Ruby extends Lang {
  constructor(p, c) { super(p, c); this.EMPTY = null; }
  close() { return 'end'; }
  ifOpen(c) { return 'if ' + c; }
  elseOpen() { return 'else'; }
  whileOpen(c) { return 'while ' + c; }
  forOpen(n, from, to) { return '(' + this.ex(from, true) + '...' + this.ex(to, true) + ').each do |' + n + '|'; }
  ref(n) { return this.isState(n) || this.isMArr(n) ? '$' + n : n; }
  idxRef(arr, i) { return (this.isMArr(arr) ? '$' + arr : arr) + '[' + (i && i._s !== undefined ? i._s : this.ex(i, true)) + ']'; }
  declS(n, e) { return n + ' = ' + e; }
  setS(n, e) { return this.ref(n) + ' = ' + e; }
  setIdxS(arr, i, e) { return (this.isMArr(arr) ? '$' + arr : arr) + '[' + i + '] = ' + e; }
  retS(e) { return 'return ' + e; }
  runS(e) { return e; }
  printS(parts, nl) {
    const items = this.parts(parts, false).map((p) => (p.text !== undefined ? single(p.text) : this.ex(p.e, false)));
    if (nl) items.push('"\\n"');
    return items.length ? 'print(' + items.join(', ') + ')' : '';
  }
  program() {
    const p = this.p;
    this.w('# ' + this.c.file + ': ' + p.title);
    this.w();
    for (const [k, v] of Object.entries(p.strs || {})) this.w(k + ' = [' + v.map(single).join(', ') + '].freeze');
    for (const [k, v] of Object.entries(p.ints || {})) this.w(k + ' = [' + v.join(', ') + '].freeze');
    for (const [k, v] of Object.entries(p.state || {})) this.w('$' + k + ' = ' + v);
    for (const [k, v] of Object.entries(p.marrs || {})) this.w('$' + k + ' = ' + (v.every((x) => x === 0) ? 'Array.new(' + v.length + ', 0)' : '[' + v.join(', ') + ']'));
    this.w();
    const fn = (name, params, body) => {
      this.w('def ' + name + (params.length ? '(' + params.join(', ') + ')' : ''));
      this.ind(() => this.stmts(body));
      this.w('end');
      this.w();
    };
    for (const f of p.funcs) fn(f.name, f.params, f.body);
    fn('main', [], p.main);
    this.w('main');
    return this.lines.join('\n') + '\n';
  }
}

class Lua extends Lang {
  constructor(p, c) { super(p, c); this.EMPTY = null; }
  close() { return 'end'; }
  ifOpen(c) { return 'if ' + c + ' then'; }
  elseOpen() { return 'else'; }
  whileOpen(c) { return 'while ' + c + ' do'; }
  forOpen(n, from, to) {
    const t = to.k === 'lit' ? String(to.v - 1) : this.ex(to, false) + ' - 1';
    return 'for ' + n + ' = ' + this.ex(from, true) + ', ' + t + ' do';
  }
  binEx(op, a, b) {
    const m = { '/': '//', '!=': '~=', '&&': 'and', '||': 'or' };
    return a + ' ' + (m[op] || op) + ' ' + b;
  }
  idxRef(arr, i) { return arr + '[' + (i && i._s !== undefined ? i._s : this.ex(i, false)) + ' + 1]'; }
  declS(n, e) { return 'local ' + n + ' = ' + e; }
  setS(n, e) { return n + ' = ' + e; }
  setIdxS(arr, i, e) { return arr + '[(' + i + ') + 1] = ' + e; }
  retS(e) { return 'return ' + e; }
  runS(e) { return e; }
  printS(parts, nl) {
    const items = this.parts(parts, false).map((p) => (p.text !== undefined ? json(p.text) : this.ex(p.e, false)));
    if (nl) items.push('"\\n"');
    return items.length ? 'io.write(' + items.join(', ') + ')' : '';
  }
  program() {
    const p = this.p;
    this.w('-- ' + this.c.file + ': ' + p.title);
    this.w();
    for (const [k, v] of Object.entries(p.strs || {})) this.w('local ' + k + ' = {' + v.map(json).join(', ') + '}');
    for (const [k, v] of Object.entries(p.ints || {})) this.w('local ' + k + ' = {' + v.join(', ') + '}');
    for (const [k, v] of Object.entries(p.state || {})) this.w('local ' + k + ' = ' + v);
    for (const [k, v] of Object.entries(p.marrs || {})) {
      if (v.every((x) => x === 0)) {
        this.w('local ' + k + ' = {}');
        this.w('for i = 1, ' + v.length + ' do ' + k + '[i] = 0 end');
      } else this.w('local ' + k + ' = {' + v.join(', ') + '}');
    }
    this.w();
    const fn = (name, params, body) => {
      this.w('local function ' + name + '(' + params.join(', ') + ')');
      this.ind(() => this.stmts(body));
      this.w('end');
      this.w();
    };
    for (const f of p.funcs) fn(f.name, f.params, f.body);
    fn('main', [], p.main);
    this.w('main()');
    return this.lines.join('\n') + '\n';
  }
}

const LANGS = {
  c: (p, c) => new C(p, c, false),
  cpp: (p, c) => new C(p, c, true),
  java: (p, c) => new Java(p, c),
  cs: (p, c) => new CSharp(p, c),
  js: (p, c) => new JS(p, c, false),
  ts: (p, c) => new JS(p, c, true),
  go: (p, c) => new Go(p, c),
  rs: (p, c) => new Rust(p, c),
  php: (p, c) => new PHP(p, c),
  py: (p, c) => new Python(p, c),
  rb: (p, c) => new Ruby(p, c),
  lua: (p, c) => new Lua(p, c),
};

function emit(lang, prog, ctx) {
  const make = LANGS[lang];
  if (!make) return null;
  const e = make(prog, ctx);
  let code = e.program();
  if (lang === 'go') code = code.replace(/^( {4})+/gm, (m) => '\t'.repeat(m.length / 4));
  return code;
}

module.exports = { emit, SUPPORTED: Object.keys(LANGS) };

};
__mods["lib/ai/lexicon.js"] = function (module, exports, require) {
'use strict';
// Vocabulary packs. Each pack is a "world" the mini generator can write about:
// who lives in it, what they do, what the terrain looks like.
//
//   words    : file-name words that select this pack
//   arche    : program shapes that suit it (first = default)
//   units    : names (characters, items, teams ...)
//   verbs    : things units do to each other
//   tiles    : 5 terrain symbols from low to high, rare : special find
//   sim      : population simulation settings
//   board    : leaderboard title

const GENERIC = {
  endings: ['at dawn', 'without warning', 'just in time', 'by accident', 'again', 'out of nowhere'],
  verbs: ['hits', 'tackles', 'surprises', 'outsmarts', 'bumps into', 'dodges'],
  tiles: [['~', 'water'], ['.', 'sand'], ['"', 'grass'], ['#', 'rock'], ['^', 'peak']],
  rare: ['*', 'treasure'],
};

const PACKS = {
  minecraft: {
    title: 'Minecraft', board: 'Top miners', arche: ['worldmap', 'battle', 'records', 'sim'],
    words: ['minecraft', 'mc', 'creeper', 'steve', 'redstone', 'nether', 'enderman', 'blocks', 'voxel', 'pickaxe', 'mojang', 'herobrine'],
    units: ['Steve', 'Alex', 'Creeper', 'Zombie', 'Skeleton', 'Enderman', 'Villager', 'Pig'],
    verbs: ['punches', 'slashes', 'shoots', 'blows up', 'stabs', 'shoves'],
    tiles: [['~', 'water'], ['.', 'sand'], ['"', 'grass block'], ['#', 'stone'], ['^', 'snow']], rare: ['*', 'diamond ore'],
    sim: { label: 'creepers', start: 12, growth: 35, cap: 600 },
  },
  space: {
    title: 'Space', board: 'Top pilots', arche: ['worldmap', 'sim', 'battle'],
    words: ['space', 'star', 'stars', 'galaxy', 'planet', 'planets', 'mars', 'moon', 'rocket', 'orbit', 'cosmos', 'nasa', 'astronaut', 'universe', 'solar', 'comet', 'nebula', 'saturn', 'jupiter', 'asteroid'],
    units: ['Nova', 'Orion', 'Vega', 'Luna', 'Atlas', 'Comet', 'Sol', 'Pulsar'],
    verbs: ['orbits', 'eclipses', 'scans', 'tows', 'docks with', 'outshines'],
    tiles: [[' ', 'void'], ['.', 'dust'], [':', 'nebula'], ['o', 'asteroid'], ['@', 'star']], rare: ['*', 'black hole'],
    sim: { label: 'stars', start: 8, growth: 25, cap: 400 },
  },
  zombie: {
    title: 'Zombie', board: 'Top survivors', arche: ['sim', 'battle', 'worldmap'],
    words: ['zombie', 'zombies', 'undead', 'virus', 'plague', 'outbreak', 'infection', 'pandemic', 'apocalypse', 'survivor', 'walker', 'epidemic', 'bacteria'],
    units: ['Walker', 'Runner', 'Brute', 'Spitter', 'Survivor', 'Medic', 'Sheriff', 'Scout'],
    verbs: ['bites', 'chases', 'barricades against', 'ambushes', 'shoves', 'outruns'],
    tiles: [['~', 'flooded road'], ['.', 'street'], ['"', 'overgrown yard'], ['#', 'ruins'], ['^', 'burning tower']], rare: ['+', 'medical supplies'],
    sim: { label: 'infected', start: 3, growth: 45, cap: 800 },
  },
  fantasy: {
    title: 'Dragon', board: 'Hall of heroes', arche: ['battle', 'worldmap', 'records'],
    words: ['dragon', 'dragons', 'dungeon', 'rpg', 'quest', 'knight', 'wizard', 'sword', 'goblin', 'elf', 'orc', 'magic', 'spell', 'fantasy', 'adventure', 'hero', 'paladin', 'troll', 'realm', 'mage'],
    units: ['Aria', 'Bram', 'Drogon', 'Grub', 'Merlin', 'Sir Lance', 'Thorn', 'Elowen'],
    verbs: ['slashes', 'hexes', 'burns', 'shields against', 'ambushes', 'duels'],
    tiles: [['~', 'sea'], ['.', 'beach'], ['"', 'forest'], ['#', 'mountain'], ['^', 'glacier']], rare: ['$', 'dragon hoard'],
    sim: { label: 'goblins', start: 6, growth: 40, cap: 500 },
  },
  ninja: {
    title: 'Ninja', board: 'Dojo ranking', arche: ['battle', 'records'],
    words: ['ninja', 'samurai', 'shogun', 'katana', 'dojo', 'shuriken', 'ronin', 'sensei', 'bushido'],
    units: ['Hayate', 'Kage', 'Ronin', 'Shadow', 'Sensei', 'Kunoichi', 'Oni', 'Tengu'],
    verbs: ['strikes', 'vanishes behind', 'parries', 'flips over', 'ambushes', 'disarms'],
    tiles: GENERIC.tiles, rare: ['*', 'scroll'], sim: { label: 'ninjas', start: 5, growth: 30, cap: 300 },
  },
  pirate: {
    title: 'Pirate', board: 'Most feared captains', arche: ['worldmap', 'battle', 'records'],
    words: ['pirate', 'pirates', 'treasure', 'ship', 'ships', 'sail', 'captain', 'kraken', 'plank', 'buccaneer', 'island', 'islands', 'anchor', 'crew'],
    units: ['Blackbeard', 'Anne', 'Calico Jack', 'Barnacle Bill', 'Kraken', 'Polly', 'Captain Hook', 'Salty'],
    verbs: ['boards', 'fires on', 'out-sails', 'plunders', 'ambushes', 'hoists a flag at'],
    tiles: [['~', 'open sea'], ['.', 'shallows'], ['"', 'jungle'], ['#', 'cliffs'], ['^', 'volcano']], rare: ['X', 'buried treasure'],
    sim: { label: 'pirates', start: 7, growth: 30, cap: 400 },
  },
  robot: {
    title: 'Robot', board: 'Top bots', arche: ['battle', 'records', 'sim'],
    words: ['robot', 'robots', 'bot', 'bots', 'cyborg', 'android', 'droid', 'skynet', 'mech', 'automaton', 'ai', 'machine', 'drone'],
    units: ['Bolt', 'Circuit', 'Servo', 'Gizmo', 'Chip', 'Titan', 'Spark', 'Widget'],
    verbs: ['zaps', 'reboots', 'overclocks', 'rewires', 'out-computes', 'short-circuits'],
    tiles: GENERIC.tiles, rare: ['*', 'power core'], sim: { label: 'robots', start: 4, growth: 38, cap: 500 },
  },
  cyber: {
    title: 'Cyber', board: 'Top netrunners', arche: ['battle', 'plot', 'records'],
    words: ['matrix', 'cyber', 'cyberpunk', 'neon', 'glitch', 'binary', 'digital', 'hack', 'hacker', 'hacking', 'terminal', 'pixel'],
    units: ['Neo', 'Zero', 'Cipher', 'Oracle', 'Glitch', 'Signal', 'Echo', 'Proxy'],
    verbs: ['hacks', 'pings', 'decrypts', 'floods', 'traces', 'spoofs'],
    tiles: [[' ', 'void'], ['.', 'static'], [':', 'noise'], ['#', 'firewall'], ['@', 'mainframe']], rare: ['*', 'root access'],
    sim: { label: 'processes', start: 5, growth: 40, cap: 500 },
  },
  animals: {
    title: 'Pet', board: 'Best in show', arche: ['records', 'sim', 'battle', 'textgen'],
    words: ['cat', 'cats', 'dog', 'dogs', 'pet', 'pets', 'animal', 'animals', 'zoo', 'puppy', 'kitten', 'bird', 'rabbit', 'hamster', 'wolf', 'bear', 'fox', 'monkey', 'monke', 'bunny', 'horse', 'panda', 'penguin'],
    units: ['Whiskers', 'Rex', 'Luna', 'Biscuit', 'Mochi', 'Shadow', 'Pepper', 'Buddy'],
    verbs: ['chases', 'pounces on', 'sniffs', 'herds', 'outruns', 'barks at'],
    tiles: [['~', 'pond'], ['.', 'dirt path'], ['"', 'meadow'], ['#', 'rocks'], ['^', 'hill']], rare: ['*', 'treat'],
    sim: { label: 'rabbits', start: 4, growth: 50, cap: 600 },
  },
  food: {
    title: 'Food', board: 'Menu favourites', arche: ['records', 'textgen', 'sim', 'battle'],
    words: ['pizza', 'burger', 'burgers', 'taco', 'tacos', 'coffee', 'donut', 'donuts', 'doughnut', 'cake', 'sushi', 'pasta', 'cookie', 'cookies', 'food', 'cooking', 'recipe', 'kitchen', 'restaurant', 'cafe', 'bakery', 'sandwich', 'fries', 'bread', 'chef', 'menu', 'snack', 'icecream', 'noodles', 'tea'],
    units: ['Pizza', 'Burger', 'Taco', 'Sushi', 'Pancake', 'Donut', 'Noodles', 'Waffle'],
    verbs: ['tops', 'wraps', 'dunks', 'slices', 'toasts', 'drizzles'],
    tiles: [['~', 'broth'], ['.', 'crumbs'], ['"', 'lettuce'], ['#', 'crust'], ['^', 'whipped cream']], rare: ['*', 'secret sauce'],
    sim: { label: 'sourdough', start: 5, growth: 35, cap: 400 },
  },
  money: {
    title: 'Money', board: 'Richest accounts', arche: ['sim', 'records', 'plot'],
    words: ['bank', 'money', 'cash', 'stock', 'stocks', 'crypto', 'bitcoin', 'market', 'economy', 'finance', 'wallet', 'coin', 'coins', 'invest', 'investing', 'budget', 'profit', 'tax', 'taxes', 'gold', 'rich', 'savings', 'interest', 'trading', 'trader'],
    units: ['Gold', 'Silver', 'Bronze', 'Dollar', 'Euro', 'Yen', 'Coin', 'Bond'],
    verbs: ['outbids', 'invests in', 'trades with', 'overtakes', 'undercuts', 'merges with'],
    tiles: GENERIC.tiles, rare: ['$', 'jackpot'], sim: { label: 'dollars', start: 100, growth: 20, cap: 2000 },
  },
  school: {
    title: 'School', board: 'Top students', arche: ['records', 'plot', 'textgen'],
    words: ['school', 'grade', 'grades', 'homework', 'math', 'maths', 'class', 'classroom', 'student', 'students', 'teacher', 'exam', 'quiz', 'study', 'college', 'university', 'gpa', 'lesson', 'algebra', 'science', 'physics', 'chemistry', 'calculus'],
    units: ['Ava', 'Ben', 'Chloe', 'Dev', 'Ella', 'Finn', 'Gus', 'Hana'],
    verbs: ['outscores', 'tutors', 'quizzes', 'challenges', 'teams up with', 'debates'],
    tiles: GENERIC.tiles, rare: ['*', 'gold star'], sim: { label: 'students', start: 10, growth: 20, cap: 300 },
  },
  cars: {
    title: 'Racing', board: 'Fastest laps', arche: ['records', 'battle', 'plot', 'sim'],
    words: ['car', 'cars', 'race', 'racing', 'racer', 'speed', 'drift', 'truck', 'traffic', 'highway', 'road', 'nitro', 'turbo', 'driving', 'driver', 'formula', 'garage', 'engine', 'motorbike', 'bike', 'lap'],
    units: ['Turbo', 'Drift', 'Nitro', 'Apex', 'Piston', 'Rocket', 'Racer', 'Blaze'],
    verbs: ['overtakes', 'drafts behind', 'cuts off', 'races', 'bumps', 'passes'],
    tiles: [['~', 'puddle'], ['.', 'asphalt'], ['"', 'roadside grass'], ['#', 'barrier'], ['^', 'ramp']], rare: ['*', 'nitro boost'],
    sim: { label: 'cars', start: 10, growth: 30, cap: 400 },
  },
  sports: {
    title: 'League', board: 'League table', arche: ['records', 'battle', 'sim'],
    words: ['football', 'soccer', 'basketball', 'baseball', 'hockey', 'tennis', 'sport', 'sports', 'league', 'team', 'teams', 'goal', 'match', 'olympics', 'golf', 'cricket', 'rugby', 'nba', 'nfl', 'fifa', 'championship', 'stadium', 'coach', 'tournament'],
    units: ['Falcons', 'Tigers', 'Sharks', 'Wolves', 'Eagles', 'Bears', 'Lions', 'Hawks'],
    verbs: ['beats', 'outplays', 'edges', 'crushes', 'tops', 'stuns'],
    tiles: [['~', 'wet pitch'], ['.', 'dirt'], ['"', 'turf'], ['#', 'stands'], ['^', 'scoreboard']], rare: ['*', 'trophy'],
    sim: { label: 'fans', start: 20, growth: 25, cap: 900 },
  },
  music: {
    title: 'Music', board: 'Top of the charts', arche: ['plot', 'records', 'textgen', 'battle'],
    words: ['music', 'song', 'songs', 'band', 'guitar', 'drum', 'drums', 'piano', 'beat', 'beats', 'rap', 'dj', 'melody', 'rhythm', 'concert', 'album', 'playlist', 'synth', 'bass', 'violin', 'jazz', 'rock', 'metal', 'lofi', 'chord'],
    units: ['Riff', 'Beat', 'Chord', 'Tempo', 'Echo', 'Bass', 'Treble', 'Rhythm'],
    verbs: ['jams with', 'duets with', 'samples', 'remixes', 'harmonizes with', 'drowns out'],
    tiles: GENERIC.tiles, rare: ['*', 'platinum record'], sim: { label: 'listeners', start: 10, growth: 40, cap: 1000 },
  },
  weather: {
    title: 'Weather', board: 'Wildest weather', arche: ['plot', 'sim', 'worldmap'],
    words: ['weather', 'rain', 'storm', 'snow', 'climate', 'cloud', 'clouds', 'wind', 'thunder', 'forecast', 'temperature', 'hurricane', 'tornado', 'fog', 'sun', 'sunny'],
    units: ['Cumulus', 'Gale', 'Drizzle', 'Blizzard', 'Thunder', 'Breeze', 'Fog', 'Hail'],
    verbs: ['rolls over', 'drenches', 'chills', 'clears', 'swirls around', 'blows past'],
    tiles: [['~', 'rain'], ['.', 'mist'], [':', 'clouds'], ['#', 'storm front'], ['^', 'snow']], rare: ['*', 'rainbow'],
    sim: { label: 'raindrops', start: 15, growth: 45, cap: 700 },
  },
  ocean: {
    title: 'Ocean', board: 'Biggest catches', arche: ['worldmap', 'sim', 'battle'],
    words: ['ocean', 'fish', 'fishing', 'shark', 'sharks', 'sea', 'whale', 'dolphin', 'reef', 'coral', 'beach', 'surf', 'water', 'diving', 'submarine', 'squid', 'octopus', 'crab', 'turtle'],
    units: ['Marlin', 'Coral', 'Orca', 'Squid', 'Dolphin', 'Eel', 'Manta', 'Jelly'],
    verbs: ['chases', 'nips', 'circles', 'outswims', 'startles', 'hides from'],
    tiles: [['~', 'deep water'], ['.', 'shallows'], ['"', 'kelp forest'], ['#', 'reef'], ['^', 'ice']], rare: ['*', 'pearl'],
    sim: { label: 'fish', start: 20, growth: 35, cap: 900 },
  },
  farm: {
    title: 'Farm', board: 'Best harvests', arche: ['sim', 'worldmap', 'records'],
    words: ['farm', 'crop', 'crops', 'tractor', 'barn', 'garden', 'plant', 'plants', 'flower', 'flowers', 'tree', 'trees', 'harvest', 'wheat', 'corn', 'seed', 'seeds', 'forest', 'jungle', 'grass', 'veggie', 'vegetable'],
    units: ['Daisy', 'Clover', 'Barley', 'Pumpkin', 'Tractor', 'Rooster', 'Hazel', 'Cornelius'],
    verbs: ['plants', 'waters', 'harvests', 'trims', 'outgrows', 'shades'],
    tiles: [['~', 'pond'], ['.', 'soil'], ['"', 'wheat field'], ['#', 'orchard'], ['^', 'haystack']], rare: ['*', 'golden pumpkin'],
    sim: { label: 'sunflowers', start: 6, growth: 40, cap: 600 },
  },
  castle: {
    title: 'Kingdom', board: 'Royal court', arche: ['worldmap', 'battle', 'records'],
    words: ['castle', 'king', 'queen', 'kingdom', 'medieval', 'royal', 'prince', 'princess', 'throne', 'empire', 'viking', 'vikings', 'fortress', 'siege', 'knights', 'crown'],
    units: ['Arthur', 'Guinevere', 'Lancelot', 'Merlin', 'Mordred', 'Percival', 'Gawain', 'Isolde'],
    verbs: ['besieges', 'knights', 'jousts', 'banishes', 'defends', 'toasts'],
    tiles: [['~', 'moat'], ['.', 'road'], ['"', 'farmland'], ['#', 'castle wall'], ['^', 'tower']], rare: ['*', 'crown jewel'],
    sim: { label: 'peasants', start: 30, growth: 20, cap: 1000 },
  },
  spooky: {
    title: 'Haunted', board: 'Scariest of all', arche: ['battle', 'textgen', 'sim'],
    words: ['ghost', 'ghosts', 'spooky', 'vampire', 'witch', 'haunted', 'halloween', 'monster', 'monsters', 'mummy', 'scary', 'horror', 'creepy', 'phantom', 'demon', 'skeleton'],
    units: ['Boo', 'Count Dusk', 'Wisp', 'Mummy', 'Witch', 'Ghoul', 'Phantom', 'Pumpkin'],
    verbs: ['haunts', 'startles', 'cackles at', 'vanishes from', 'whispers to', 'curses'],
    tiles: [['~', 'swamp'], ['.', 'graveyard dirt'], ['"', 'dead grass'], ['#', 'crypt'], ['^', 'haunted hill']], rare: ['*', 'cursed relic'],
    sim: { label: 'ghosts', start: 4, growth: 42, cap: 450 },
  },
  dino: {
    title: 'Dinosaur', board: 'Apex predators', arche: ['battle', 'sim', 'worldmap'],
    words: ['dino', 'dinos', 'dinosaur', 'dinosaurs', 'trex', 'jurassic', 'raptor', 'fossil', 'prehistoric', 'mammoth'],
    units: ['Rex', 'Spike', 'Raptor', 'Stego', 'Bronto', 'Ptera', 'Trike', 'Ankylo'],
    verbs: ['stomps', 'roars at', 'chomps', 'charges', 'outruns', 'tail-whips'],
    tiles: [['~', 'tar pit'], ['.', 'mud'], ['"', 'fern forest'], ['#', 'cliff'], ['^', 'volcano']], rare: ['*', 'fossil'],
    sim: { label: 'raptors', start: 5, growth: 35, cap: 500 },
  },
  alien: {
    title: 'Alien', board: 'Invasion leaders', arche: ['battle', 'sim', 'worldmap'],
    words: ['alien', 'aliens', 'ufo', 'martian', 'invader', 'invaders', 'extraterrestrial', 'abduction', 'scifi'],
    units: ['Zorg', 'Blip', 'Xylo', 'Glorp', 'Zenith', 'Quark', 'Vex', 'Orbo'],
    verbs: ['abducts', 'zaps', 'beams up', 'out-warps', 'probes', 'befriends'],
    tiles: [['~', 'green ocean'], ['.', 'purple sand'], ['"', 'moss'], ['#', 'crystal'], ['^', 'crater rim']], rare: ['*', 'alien artifact'],
    sim: { label: 'invaders', start: 3, growth: 45, cap: 500 },
  },
  hero: {
    title: 'Hero', board: 'Hall of heroes', arche: ['battle', 'records'],
    words: ['superhero', 'villain', 'comic', 'cape', 'justice', 'mutant', 'avenger', 'avengers', 'sidekick', 'powers'],
    units: ['Captain Comet', 'Nightowl', 'Doctor Gravity', 'Ms. Lightning', 'Baron Blight', 'The Glitch', 'Turbo Kid', 'Mighty Moth'],
    verbs: ['punches', 'zaps', 'freezes', 'out-flies', 'foils', 'shatters'],
    tiles: GENERIC.tiles, rare: ['*', 'power crystal'], sim: { label: 'villains', start: 3, growth: 35, cap: 300 },
  },
  circus: {
    title: 'Circus', board: 'Star performers', arche: ['records', 'battle', 'textgen'],
    words: ['circus', 'clown', 'clowns', 'carnival', 'fair', 'magic', 'magician', 'juggle', 'acrobat', 'funfair', 'amusement', 'theme', 'park', 'rollercoaster'],
    units: ['Ringmaster', 'Acrobat', 'Juggler', 'Strongman', 'Clown', 'Magician', 'Lion Tamer', 'Unicyclist'],
    verbs: ['juggles', 'out-flips', 'startles', 'applauds', 'swaps hats with', 'honks at'],
    tiles: GENERIC.tiles, rare: ['*', 'golden ticket'], sim: { label: 'visitors', start: 20, growth: 30, cap: 800 },
  },
  transit: {
    title: 'Transit', board: 'Busiest lines', arche: ['records', 'sim', 'plot'],
    words: ['train', 'trains', 'rail', 'railway', 'subway', 'metro', 'bus', 'tram', 'station', 'airplane', 'plane', 'planes', 'pilot', 'airport', 'flight', 'jet', 'boat', 'ferry', 'taxi', 'transit', 'commute'],
    units: ['Express', 'Local', 'Freight', 'Monorail', 'Tram', 'Bullet', 'Steamer', 'Metro'],
    verbs: ['overtakes', 'waits for', 'links to', 'departs before', 'merges with', 'passes'],
    tiles: GENERIC.tiles, rare: ['*', 'express stop'], sim: { label: 'passengers', start: 30, growth: 30, cap: 900 },
  },
  internet: {
    title: 'Network', board: 'Fastest servers', arche: ['sim', 'records', 'battle'],
    words: ['web', 'server', 'servers', 'network', 'wifi', 'cloud', 'browser', 'website', 'internet', 'data', 'database', 'router', 'api', 'online', 'download', 'upload', 'ping', 'packet', 'packets', 'chat', 'email', 'login', 'proxy', 'dns', 'cache'],
    units: ['Router', 'Server', 'Laptop', 'Phone', 'Modem', 'Switch', 'Firewall', 'Cache'],
    verbs: ['pings', 'queries', 'routes to', 'syncs with', 'blocks', 'backs up'],
    tiles: GENERIC.tiles, rare: ['*', 'open port'], sim: { label: 'packets', start: 10, growth: 50, cap: 1000 },
  },
  arcade: {
    title: 'Arcade', board: 'High scores', arche: ['records', 'battle', 'worldmap'],
    words: ['game', 'games', 'arcade', 'retro', 'player', 'players', 'gaming', 'gamer', 'level', 'boss', 'console', 'joystick', 'highscore', 'platformer', 'roguelike', 'tetris', 'pong', 'snake', 'chess', 'mario', 'pacman', 'sudoku'],
    units: ['Pixel', 'Sprite', 'Joystick', 'Boss', 'Combo', 'Glitch', 'Respawn', 'Bonus'],
    verbs: ['stomps', 'combos', 'dodges', 'power-ups', 'speedruns past', 'respawns near'],
    tiles: [['~', 'lava'], ['.', 'floor'], ['"', 'bush'], ['#', 'brick'], ['^', 'spikes']], rare: ['*', 'extra life'],
    sim: { label: 'sprites', start: 5, growth: 40, cap: 400 },
  },
  crypto: {
    title: 'Vault', arche: ['vault'],
    words: ['secret', 'secrets', 'cipher', 'encrypt', 'encryption', 'decrypt', 'cryptography', 'hash', 'password', 'passwords', 'lock', 'vault', 'key', 'keys', 'safe', 'enigma', 'caesar', 'xor', 'token', 'security'],
    units: [], verbs: [],
  },
  // ---- humour: these write jokes rather than simulations
  yomama: {
    title: 'Ur mom', board: 'Ur mom', arche: ['textgen'],
    words: ['mom', 'mum', 'mama', 'mother', 'yomama', 'yomom', 'urmom', 'urmum', 'yourmom'],
    prefix: 'Ur mom is so ', mid: ' that ', suffix: '.',
    pairs: [
      ['old', 'her birthday candles set off the fire department'],
      ['tall', 'she has to duck when the moon goes by'],
      ['forgetful', 'she went looking for her keys and they were in her hand'],
      ['lazy', 'she hired a robot to press snooze for her'],
      ['smart', 'her calculator asks her for help'],
      ['slow', 'a snail waved at her while she was still tying her shoe'],
      ['loud', 'her whisper shows up on seismographs'],
      ['generous', 'she tips the GPS for good directions'],
    ],
  },
  dadjoke: {
    title: 'Dad joke', board: 'Dad jokes', arche: ['textgen'],
    words: ['joke', 'jokes', 'dad', 'pun', 'puns', 'funny', 'humor', 'humour', 'punchline', 'comedy', 'lol', 'haha'],
    prefix: '', mid: ' ', suffix: '',
    pairs: [
      ["Why don't scientists trust atoms?", 'Because they make up everything.'],
      ['Why did the scarecrow win an award?', 'He was outstanding in his field.'],
      ['What do you call a fake noodle?', 'An impasta.'],
      ['Why did the bicycle fall over?', 'It was two tired.'],
      ['How does a penguin build its house?', 'Igloos it together.'],
      ['What do you call cheese that is not yours?', 'Nacho cheese.'],
      ['Why can\'t you give Elsa a balloon?', 'She will let it go.'],
      ['What do you call a bear with no teeth?', 'A gummy bear.'],
    ],
  },
  roast: {
    title: 'Code roast', board: 'Code roast', arche: ['textgen'],
    words: ['roast', 'roasts', 'burn', 'burns', 'insult', 'insults', 'diss', 'trashtalk', 'banter', 'sassy'],
    prefix: 'Your code is so ', mid: ' that ', suffix: '.',
    pairs: [
      ['slow', 'the compiler takes a coffee break'],
      ['messy', 'git blame gives up'],
      ['long', 'it has its own table of contents'],
      ['tangled', 'the debugger asked for a map'],
      ['nested', 'it needs a ladder to read'],
      ['cryptic', 'even the comments are in riddles'],
      ['optimistic', 'it has no error handling'],
      ['bloated', 'it ships with its own weather system'],
    ],
  },
  meme: {
    title: 'Meme', board: 'Meme leaderboard', arche: ['textgen', 'records'],
    words: ['meme', 'memes', 'skibidi', 'rizz', 'sigma', 'npc', 'vibe', 'vibes', 'based', 'cringe', 'brainrot', 'slay', 'yeet', 'bruh', 'sus', 'amogus', 'troll', 'doge', 'pog', 'poggers', 'gigachad', 'chad'],
    units: ['Doge', 'Gigachad', 'Skibidi', 'The NPC', 'Sussy Baka', 'Ohio', 'Grimace', 'Bruh'],
    verbs: ['out-rizzes', 'yeets', 'side-eyes', 'vibes with', 'memes', 'ratios'],
    endings: ['no cap', 'for the plot', 'in Ohio', 'and nobody knows why', 'on a Tuesday', 'respectfully'],
    tiles: GENERIC.tiles, rare: ['*', 'rare pepe'], sim: { label: 'memes', start: 3, growth: 55, cap: 900 },
  },
  fortune: {
    title: 'Fortune cookie', board: 'Lucky numbers', arche: ['textgen'],
    words: ['fortune', 'fortunes', 'horoscope', 'zodiac', 'luck', 'lucky', 'prophecy', 'wisdom', 'quote', 'quotes', 'proverb', 'oracle', 'tarot', 'destiny'],
    prefix: 'You will ', mid: ' ', suffix: '.',
    pairs: [
      ['find a lucky coin', 'on a very ordinary Tuesday'],
      ['meet a helpful stranger', 'right when you need one'],
      ['finally fix that bug', 'just after you stop looking'],
      ['learn something new', 'from an unexpected teacher'],
      ['take a small risk', 'and be glad you did'],
      ['get good news', 'before the week is over'],
      ['discover a hidden talent', 'while doing something silly'],
      ['make a friend', 'over a shared snack'],
    ],
  },
};

// Words that choose a program shape regardless of theme.
const ARCHE_WORDS = {
  worldmap: ['world', 'worlds', 'map', 'maps', 'terrain', 'biome', 'biomes', 'landscape', 'continent', 'overworld', 'worldgen', 'procedural'],
  battle: ['battle', 'battles', 'fight', 'fighting', 'fighter', 'arena', 'war', 'boss', 'pvp', 'duel', 'versus', 'vs', 'combat', 'attack', 'brawl', 'smash', 'showdown'],
  records: ['score', 'scores', 'leaderboard', 'rank', 'ranking', 'rankings', 'top', 'stats', 'standings', 'winners', 'scoreboard', 'highscores'],
  sim: ['sim', 'simulation', 'simulator', 'spread', 'growth', 'population', 'evolve', 'evolution', 'ecosystem', 'colony', 'breeding'],
  plot: ['plot', 'graph', 'chart', 'wave', 'waves', 'sine', 'sin', 'curve', 'function', 'parabola', 'sawtooth', 'oscilloscope'],
  textgen: ['generator', 'random', 'sentence', 'sentences', 'story', 'stories', 'phrase', 'phrases', 'lines', 'words', 'mad', 'madlibs'],
  mandel: ['mandelbrot', 'mandel', 'fractal', 'julia', 'fractals'],
  life: ['life', 'conway', 'gol', 'cellular', 'automata', 'automaton'],
};

module.exports = { PACKS, ARCHE_WORDS, GENERIC };

};
__mods["extension.js"] = function (module, exports, require) {
'use strict';
const vscode = require('vscode');
const gen = require('./lib/generator');
const { Typist } = require('./lib/typist');
const ai = require('./lib/ai');

/** @type {null | {cancelled: boolean, wake: null | (() => void)}} */
let session = null;
let statusItem = null;
let keyHandler = null;
let noticeShown = false;

// ---------------------------------------------------------------- activation

function activate(context) {
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 1000);
  statusItem.command = 'editorUtils.stop';
  context.subscriptions.push(
    statusItem,
    vscode.commands.registerCommand('editorUtils.start', () => start(context)),
    vscode.commands.registerCommand('editorUtils.stop', () => stop()),
    vscode.commands.registerCommand('editorUtils.setApiKey', () => setApiKey(context)),
    vscode.commands.registerCommand('editorUtils.key', () => { if (keyHandler) keyHandler(); }),
  );
}

function deactivate() {
  stop();
}

function stop() {
  if (!session) return;
  session.cancelled = true;
  if (session.wake) session.wake();
}

// ---------------------------------------------------------------- main flow

async function start(context) {
  // Pressing the hotkey again while typing toggles it off.
  if (session) {
    stop();
    return;
  }

  const cfg = vscode.workspace.getConfiguration('editorUtils');

  const input = await vscode.window.showInputBox({
    title: 'New File',
    prompt: 'File name (include the extension, e.g. app.py)',
    placeHolder: 'untitled.py',
    validateInput: (v) => {
      const t = v.trim();
      if (!t) return 'Enter a file name';
      if (/[\\/:*?"<>|]/.test(t)) return 'Enter a file name without slashes or special characters';
      return null;
    },
  });
  if (!input) return;

  let fileName = input.trim();
  if (!gen.splitName(fileName).ext) {
    const pick = await vscode.window.showQuickPick(
      gen.LANGUAGE_CHOICES.map((l) => ({ label: l.label, description: '.' + l.ext, ext: l.ext })),
      { title: 'Language for "' + fileName + '"', placeHolder: 'Pick a language' },
    );
    if (!pick) return;
    fileName += '.' + pick.ext;
  }

  // Create the file (real file if a folder is open, otherwise an untitled buffer).
  let doc;
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (folder) {
    const uri = vscode.Uri.joinPath(folder.uri, fileName);
    let exists = false;
    try {
      await vscode.workspace.fs.stat(uri);
      exists = true;
    } catch (e) { /* does not exist yet */ }
    if (exists) {
      const answer = await vscode.window.showWarningMessage(fileName + ' already exists. Overwrite it?', { modal: true }, 'Overwrite');
      if (answer !== 'Overwrite') return;
    } else {
      await vscode.workspace.fs.writeFile(uri, new Uint8Array());
    }
    doc = await vscode.workspace.openTextDocument(uri);
  } else {
    doc = await vscode.workspace.openTextDocument(vscode.Uri.parse('untitled:' + fileName));
  }
  const editor = await vscode.window.showTextDocument(doc, { preview: false });
  if (doc.getText().length) {
    await editor.edit((eb) => eb.delete(new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length))));
  }

  // Generate the code.
  const code = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: 'Loading...' },
    (_progress, token) => buildCode(context, fileName, cfg, token),
  );
  if (!code) return;

  // Type it.
  session = { cancelled: false, wake: null };
  await vscode.commands.executeCommand('setContext', 'editorUtils.typing', true);
  statusItem.text = '$(file) ' + fileName;
  statusItem.tooltip = 'Click (or press Esc / Cmd+Ctrl+H) to stop';
  if (cfg.get('showStatus', false)) statusItem.show();

  let finished = false;
  try {
    if (cfg.get('mode', 'keystroke') === 'auto') {
      finished = await typeInto(doc, code, {
        speed: Math.max(0.25, cfg.get('speed', 1)),
        typoRate: cfg.get('typos', true) ? cfg.get('typoRate', 0.035) : 0,
        ext: gen.splitName(fileName).ext,
        label: fileName,
      });
    } else {
      finished = await keystrokeInto(doc, code, {
        typoRate: cfg.get('typos', true) ? cfg.get('typoRate', 0.035) : 0,
        ext: gen.splitName(fileName).ext,
        label: fileName,
      });
    }
  } catch (err) {
    vscode.window.showErrorMessage('Editor Utilities: ' + (err && err.message ? err.message : err));
  } finally {
    session = null;
    statusItem.hide();
    await vscode.commands.executeCommand('setContext', 'editorUtils.typing', false);
  }

  if (finished && cfg.get('saveWhenDone', true) && !doc.isUntitled && !doc.isClosed) {
    await doc.save();
  }
}

// ---------------------------------------------------------------- code generation
// Order: built-in library of well-known programs (donut.c, matrix.py ...)
//        -> Claude via your Anthropic API key -> VS Code language model (Copilot)
//        -> generic built-in template.

const SECRET_KEY = 'editorUtils.anthropicKey';
const rootOf = (context) => context.extensionPath || '/ext';

async function setApiKey(context) {
  const key = await vscode.window.showInputBox({
    title: 'Editor Utilities: API key',
    prompt: 'Stored in VS Code secret storage. Used only to write code from your file names. Leave empty to remove it.',
    password: true,
    ignoreFocusOut: true,
  });
  if (key === undefined) return;
  if (key.trim()) {
    await context.secrets.store(SECRET_KEY, key.trim());
    vscode.window.showInformationMessage('Editor Utilities: API key saved.');
  } else {
    await context.secrets.delete(SECRET_KEY);
    vscode.window.showInformationMessage('Editor Utilities: API key removed.');
  }
}

function aiPrompt(fileName) {
  const { ext } = gen.splitName(fileName);
  return (
    'Write one complete, self-contained ' + gen.languageName(ext) + ' source file named "' + fileName + '".\n' +
    'The file name decides what the program is. Famous names mean the famous program: donut.c is the classic ' +
    'spinning ASCII donut, matrix.py is falling green code, snake.js is the snake game, and so on. If the name is ' +
    'vague, write a fun, impressive program that the name plausibly suggests. It must be real working code ' +
    'that runs as-is, 30 to 120 lines, with correct syntax. Keep it legitimate and harmless. ' +
    'Output ONLY the raw source code: no markdown fences, no explanations.'
  );
}

function cleanAiText(text) {
  text = text.replace(/^\s*```[\w+#.-]*\n/, '').replace(/\n```\s*$/, '');
  return text.trim().length > 20 ? gen.normalize(text) : null;
}

async function buildCode(context, fileName, cfg, token) {
  // 1. Built-in library of exact classics (donut.c, fizzbuzz.py ...).
  const known = gen.renderProgram(rootOf(context), fileName);
  if (known) return known.code;

  // 2. The built-in name analyzer. When it recognises the name it is instant and offline.
  const mini = ai.generate(fileName);
  if (mini && mini.analysis.archetype === 'vault') return gen.render(rootOf(context), fileName).code;
  if (mini && mini.code && mini.analysis.confident) return mini.code;

  // 3. Claude through the Anthropic API, for names the analyzer does not know.
  const apiKey = await context.secrets.get(SECRET_KEY);
  if (apiKey) {
    try {
      const text = await fromAnthropic(fileName, apiKey, cfg.get('model', 'claude-sonnet-5-5'), token);
      if (text) return text;
    } catch (e) {
      if (token.isCancellationRequested) return null;
      vscode.window.showWarningMessage('Editor Utilities: the request failed (' + (e && e.message ? e.message : e) + ').');
    }
  }
  if (token.isCancellationRequested) return null;

  // 4. A VS Code language model, e.g. GitHub Copilot.
  let usedAi = !!apiKey;
  if (cfg.get('useLanguageModel', true) && vscode.lm && vscode.lm.selectChatModels) {
    try {
      const text = await fromLanguageModel(fileName, token);
      if (text) return text;
    } catch (e) { /* fall through */ }
  }
  if (token.isCancellationRequested) return null;

  // 5. The analyzer's best guess from the words in the name.
  if (mini && mini.code) {
    if (!usedAi && !noticeShown) {
      noticeShown = true;
      vscode.window.showInformationMessage(
        'Editor Utilities: guessed content for "' + fileName + '". Add an API key for smarter results.',
        'Set API Key',
      ).then((choice) => { if (choice === 'Set API Key') setApiKey(context); });
    }
    return mini.code;
  }

  // 6. Generic template (languages the analyzer cannot write yet).
  return gen.render(rootOf(context), fileName).code;
}

async function fromAnthropic(fileName, apiKey, model, token) {
  const controller = new AbortController();
  const sub = token.onCancellationRequested(() => controller.abort());
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true', // lets the request work from vscode.dev
      },
      body: JSON.stringify({
        model,
        max_tokens: 4096,
        system: 'You write source code files. You output only raw code, never markdown fences or commentary.',
        messages: [{ role: 'user', content: aiPrompt(fileName) }],
      }),
    });
    if (!res.ok) {
      let detail = '';
      try { detail = ((await res.json()).error || {}).message || ''; } catch (e) { /* ignore */ }
      throw new Error('HTTP ' + res.status + (detail ? ': ' + detail : ''));
    }
    const data = await res.json();
    const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
    return cleanAiText(text);
  } finally {
    clearTimeout(timer);
    sub.dispose();
  }
}

async function fromLanguageModel(fileName, token) {
  const models = await vscode.lm.selectChatModels({});
  if (!models.length) return null;

  const cts = new vscode.CancellationTokenSource();
  const sub = token.onCancellationRequested(() => cts.cancel());
  const timer = setTimeout(() => cts.cancel(), 30000);
  try {
    const response = await models[0].sendRequest([vscode.LanguageModelChatMessage.User(aiPrompt(fileName))], {}, cts.token);
    let text = '';
    for await (const fragment of response.text) text += fragment;
    return cleanAiText(text);
  } finally {
    clearTimeout(timer);
    sub.dispose();
    cts.dispose();
  }
}

// ---------------------------------------------------------------- typing engine
// Both modes drive the same Typist (lib/typist.js), which models one key press
// at a time: auto-closing pairs, overtype, block expansion, human mistakes.
// Keystroke mode = YOU press the keys. Auto mode = a timer presses them.

const rand = (a, b) => a + Math.random() * (b - a);
const randInt = (a, b) => Math.floor(rand(a, b + 1));

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(() => { if (session) session.wake = null; resolve(); }, ms);
    if (session) session.wake = () => { clearTimeout(t); session.wake = null; resolve(); };
  });
}

const visibleEditorFor = (doc) => vscode.window.visibleTextEditors.find((e) => e.document === doc);

/** Apply one Typist step to the real document and move the real cursor. */
async function applyStep(ed, doc, step, edge) {
  if (step.op) {
    const op = step.op;
    await ed.edit((eb) => {
      if (op.text !== undefined) eb.insert(doc.positionAt(op.at), op.text);
      else eb.delete(new vscode.Range(doc.positionAt(op.at), doc.positionAt(op.at + op.del)));
    }, { undoStopBefore: !!(edge && edge.first), undoStopAfter: false });
  }
  const p = doc.positionAt(step.cursor);
  ed.selection = new vscode.Selection(p, p);
  ed.revealRange(new vscode.Range(p, p));
}

/** Safety net: whatever happened, the finished file must be exactly the generated code. */
async function settle(doc, code) {
  const ed = visibleEditorFor(doc);
  if (!ed) return;
  if (doc.getText() !== code) {
    await ed.edit((eb) => eb.replace(new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length)), code),
      { undoStopBefore: false, undoStopAfter: true });
  } else {
    await ed.edit((eb) => eb.insert(doc.positionAt(doc.getText().length), ''), { undoStopBefore: false, undoStopAfter: true });
  }
  const end = doc.positionAt(code.length);
  ed.selection = new vscode.Selection(end, end);
  ed.revealRange(new vscode.Range(end, end));
}

// ---- auto mode: a timer presses the keys with a human rhythm

function delayFor(step, st, base) {
  const ch = step.ch || '';
  let d = st.burst > 0 ? (st.burst--, rand(16, 34)) : base * rand(0.55, 1.45);
  if (step.kind === 'enter') {
    d = rand(140, 380);
    if (step.blankNext) d += rand(150, 500);
    if (Math.random() < 0.06) d += rand(700, 2000); // thinking
  } else if (step.kind === 'skip') {
    d = rand(150, 320); // reaching for the arrow key
  } else if (step.kind === 'del') {
    d = rand(45, 110);
  } else if (step.kind === 'overtype') {
    d *= 0.8;
  } else {
    if (st.burst === 0 && /[a-z]/.test(ch) && Math.random() < 0.12) st.burst = randInt(3, 8);
    if (ch === ' ') d *= 1.15;
    if (/[(){}[\];,.:=]/.test(ch)) d *= 1.4;
    if (/[A-Z]/.test(ch)) d *= 1.3;
  }
  if (step.notice) d += rand(250, 750); // the "wait, that's wrong" beat
  return d;
}

async function typeInto(doc, code, opts) {
  const typist = new Typist(code, opts.ext, { typoRate: opts.typoRate });
  const base = 65 / opts.speed;
  const st = { burst: 0 };
  let first = true;

  while (!typist.done) {
    if (session.cancelled || doc.isClosed) return false;
    const ed = visibleEditorFor(doc);
    if (!ed) {
      // The user switched tabs: pause until the file is visible again.
      statusItem.text = '$(file) ' + opts.label;
      await sleep(300);
      continue;
    }
    const step = typist.step();
    if (!step) break;
    await applyStep(ed, doc, step, { first });
    first = false;
    statusItem.text = '$(file) ' + opts.label;
    await sleep(delayFor(step, st, base) / opts.speed);
  }
  if (session.cancelled) return false;
  await settle(doc, code);
  return true;
}

// ---- keystroke mode: YOU press the keys, each press is exactly one Typist step

async function keystrokeInto(doc, code, opts) {
  const typist = new Typist(code, opts.ext, { typoRate: opts.typoRate });
  let queued = 0;
  let pumping = false;
  let first = true;
  let typeReg = null;
  let resolveDone;
  const done = new Promise((r) => { resolveDone = r; });

  const pump = async () => {
    if (pumping) return;
    pumping = true;
    try {
      while (queued > 0 && !typist.done && !session.cancelled) {
        const ed = visibleEditorFor(doc);
        if (!ed) { queued = 0; break; }
        queued--;
        const step = typist.step();
        if (!step) break;
        await applyStep(ed, doc, step, { first });
        first = false;
        statusItem.text = '$(file) ' + opts.label;
      }
    } finally {
      pumping = false;
    }
    if (typist.done && !session.cancelled) {
      await settle(doc, code);
      resolveDone(true);
    }
  };

  const onKey = () => {
    queued = Math.min(queued + 1, 6);
    pump();
  };

  session.wake = () => resolveDone(false);
  try {
    // Take over typing while this session runs.
    try {
      typeReg = vscode.commands.registerCommand('type', (args) => {
        const active = vscode.window.activeTextEditor;
        if (active && active.document === doc) { onKey(); return undefined; }
        return vscode.commands.executeCommand('default:type', args);
      });
    } catch (e) {
      vscode.window.showWarningMessage('Another extension (Vim mode?) already owns typing, so only Enter/Backspace/Tab will work. Set editorUtils.mode to "auto" for hands-free mode.');
    }
    keyHandler = onKey;
    await vscode.commands.executeCommand('setContext', 'editorUtils.keystroke', true);
    statusItem.text = '$(file) ' + opts.label;
    return await done;
  } finally {
    keyHandler = null;
    if (typeReg) typeReg.dispose();
    await vscode.commands.executeCommand('setContext', 'editorUtils.keystroke', false);
  }
}

module.exports = { activate, deactivate };

};
var ext = __require('', 'extension.js');
exports.activate = ext.activate;
exports.deactivate = ext.deactivate;
})();
