# think-touch

A pure-Rust userspace driver for the Synaptics / Validity **Metallica MIS**
fingerprint sensor (USB id `06cb:009a`) found on the ThinkPad P70 and a
handful of other Lenovo laptops from that era.

> Status: TLS-PSK channel + cmd-`0x02` capture pipeline working. Identify
> matcher state machine doesn't fully initialise yet — investigation
> ongoing (see `TODO_TOMORROW.md`).
>
> 108 unit tests, lint-clean, MPL-2.0.

## Why another driver?

The only working free-software stack today is
[`python-validity`](https://github.com/uunicorn/python-validity), which
talks to the same family of sensors and plugs into `libfprint` /
`fprintd`. It works, but the implementation is hard to embed in
non-`fprintd` workflows, and the runtime story (system-wide Python +
`libgmp` + a GLib service) is fragile to ship.

`think-touch` aims to be:

* **Pure Rust**, so a single static binary can drive the sensor.
* **Library-first**, so the driver can be embedded in custom auth flows
  (kernel locks, `pam_exec`, GUI prompts, …) without `fprintd`.
* **Small and auditable**, MPL-2.0 licensed.

## Hardware target

| VID    | PID    | Codename       | Notes                          |
|--------|--------|----------------|--------------------------------|
| `06cb` | `009a` | Metallica MIS  | ThinkPad P70 / T480 / X1 C6 — primary target |
| `138a` | `0090` | Prometheus     | Recognised, not yet driven     |
| `138a` | `0097` | Prometheus 97  | Recognised, not yet driven     |
| `138a` | `009d` | Prometheus 9d  | Recognised, not yet driven     |

## Prior art and protocol references

* [`uunicorn/python-validity`](https://github.com/uunicorn/python-validity)
  — reference implementation, supports the full pairing + enroll +
  identify cycle.
* [`nmikhailov/Validity90`](https://github.com/nmikhailov/Validity90) —
  original reverse-engineering effort and protocol notes for the family.
* [Reversing a Fingerprint Reader Protocol — Neodyme](https://neodyme.io/en/blog/fingerprint_reversing/)
  — write-up of the TLS-PSK-over-USB scheme used by these sensors.

The sensors speak a vendor protocol over USB bulk endpoints. After a
short cleartext handshake, the host pairs with the device and from then
on every command/response is wrapped in a TLS-PSK session. The PSK is
derived from values stored in firmware-flashed persistent storage; we
will reuse the same pairing trick `python-validity` does (overwriting
the PSK during initial pairing).

## Building

```sh
cargo build --release
```

To talk to the sensor without root, install the udev rules shipped in
`packaging/udev/`:

```sh
sudo cp packaging/udev/70-think-touch.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
```

## Usage

All commands require sudo until DMI serial becomes readable for the
target user (a separate setcap step we haven't shipped yet).

### Read-only diagnostics (safe to run anytime)

```sh
think-touch list                # enumerate supported sensors on the bus
think-touch identify            # open the first supported sensor and print descriptors
think-touch version             # cleartext RomInfo (cmd 0x01)
think-touch boot-info           # cleartext probes 01 / 19 / 43 02
think-touch flash-read          # dump TLS pairing record (partition 1)
think-touch pairing             # decrypt + verify the per-host TLS keys
think-touch gwk                 # derive pre-TLS GWK keys offline (no I/O)
think-touch tls-hello           # exchange a Client Hello, parse Server Hello
think-touch tls-handshake       # full TLS-PSK handshake + RomInfo round trip
think-touch identify-sensor     # cmd 0x75 → silicon revision (FM-3367-001 etc.)
think-touch fwext-info          # cmd 0x43 02 over TLS, structured fwext info
think-touch flash-info          # cmd 0x3e: chip JEDEC id + partition table
think-touch tls-read-flash <P>  # post-TLS read of partition P (1, 2, 4, 5, 6)
think-touch db-info             # cmd 0x45: DB occupancy
think-touch db-children <id>    # cmd 0x46: walk DB tree
think-touch db-value <id>       # cmd 0x49: dump record bytes
think-touch factory-bits        # cmd 0x6f: factory TLV table
think-touch factory-calibration # subst_value byte for IDENTIFY/ENROLL
think-touch send <hex>          # arbitrary post-TLS command (protocol exploration)
think-touch int-watch           # passive EP 0x83 reader (Ctrl-C to stop)
think-touch int-probe <hex>     # send <hex> + dump resulting interrupts
think-touch diagnose            # one-shot: every read-only query in sequence
think-touch reset               # USB-reset the sensor (recovers stuck state)
think-touch forget              # delete cached pairing record
```

### Capture / matcher (in-progress)

```sh
think-touch try-calibrate                          # send a CALIBRATE cmd 0x02 and dump frames
think-touch save-calib                             # 3-pass calibration → /var/lib/think-touch/calib_data
think-touch try-identify [--use-saved-calib | --use-stored-calib]
                                                    # send IDENTIFY + interrupt dance
                                                    # (matcher init still being debugged)
think-touch match-finger                           # cmd 0x5e — only after a successful IDENTIFY
think-touch blink                                  # exercise the LED control path
```

### One-time setup

To talk to the sensor without root, install the udev rules:

```sh
sudo install -m 644 packaging/udev/70-think-touch.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger --action=add --attr-match=idVendor=06cb --attr-match=idProduct=009a
```

Note: even with the udev rule, this binary still needs root for DMI
serial access (`/sys/class/dmi/id/product_serial`). A future setcap
step will fix this.

## Attribution

Protocol knowledge (USB endpoint addresses, cleartext command bytes,
response framing) is derived from the public reverse-engineering work
listed in [`THIRD_PARTY.md`](./THIRD_PARTY.md). No source code is
copied; only protocol facts are encoded in our Rust source.

## License

Mozilla Public License 2.0. See [`LICENSE`](./LICENSE).
