# Third-party attribution

`synaptics-metallica-mis` itself is licensed under the Mozilla Public License 2.0
(see [`LICENSE`](./LICENSE)). The list below documents external work
that influenced this codebase.

## Protocol knowledge

The Validity / Synaptics command framing, USB endpoint conventions and
the cleartext bootstrap commands implemented in `src/protocol.rs` were
learned from the following public reverse-engineering projects. **No
source code is copied** — only protocol facts (endpoint addresses,
opcode bytes, response layouts) are encoded in our Rust source.

### `uunicorn/python-validity` — MIT

```
MIT License

Copyright (c) 2020 uunicorn

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### Vendor command capsules (`init_hardcoded`, etc.)

The byte-array constants in `src/blobs.rs` are reproduced verbatim from
`python-validity/validitysensor/blobs_9a.py` (MIT). They are opaque
Synaptics/Lenovo command capsules — likely TLS-wrapped configuration
messages — that the device requires during boot. We redistribute them
under MIT compatibility.

### `nmikhailov/Validity90` — protocol specifications and notes

Source: https://github.com/nmikhailov/Validity90 — used as a
specification document, not as code. The repository ships protocol
notes (`docs/`), a Wireshark dissector and a prototype implementation;
none of that source has been copied into `synaptics-metallica-mis`.

### Lenovo firmware extension (`xpfwext`)

The firmware-extension blob `6_07f_lenovo_mis_qm.xpfwext` is shipped by
Lenovo inside their Windows fingerprint driver installer:

  https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe

`synaptics-metallica-mis` does not redistribute the blob. The URL above is the
canonical source documented by `python-validity`'s
`validitysensor/firmware_tables.py`.

### Neodyme / Th0mas blog post

> "Reversing a Fingerprint Reader Protocol" — https://neodyme.io/en/blog/fingerprint_reversing/

Used as background reading on the TLS-PSK over-USB scheme. No code or
verbatim text imported.
