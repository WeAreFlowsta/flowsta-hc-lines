# flowsta-hc-lines

Run two Holochain lines side by side in a desktop app, and move a person's data from the old line to the new one.

A Holochain *line* is a series of releases that share a network and data format: 0.6.x is one line, 0.7.x the next. Moving between lines is a breaking change. Your app's conductor and key store change version, your DNAs get new hashes and therefore new networks, and a person's own data sits in a cell the new conductor cannot open. This library holds the pieces an app needs to get through that without putting anyone's data at risk:

- run the old line's conductor and key store beside the new one, on one machine, under one app;
- copy the person's own records from the old line to the new one, idempotently, resuming after a crash;
- keep writing to both lines while another of the person's devices is still on the older app;
- retire the old line from local facts once nothing needs it;
- keep a verified copy of each line's conductor (a *kit*) in the app's data folder, so the next move runs from disk.

## Status

**Early.** The machinery runs in production in [Flowsta Vault](https://flowsta.com/vault), which moved its users from Holochain 0.6.1 to 0.7.1, and is being extracted into this library. The public interface is not stable yet; expect breaking changes until 1.0.

## Lines are features

Each line is a Cargo feature that pins the exact client crate versions its conductor needs:

| Feature | Conductor | `holochain_client` | `holochain_types` | `lair_keystore_api` | `mr_bundle` |
|---|---|---|---|---|---|
| `line-06` | 0.6.1 | =0.8.1 | =0.6.1 | =0.6.3 | =0.6.1 |
| `line-07` | 0.7.1 | =0.9.1 | =0.7.1 | =0.7.1 | =0.7.1 |

Use those crates through the library's re-exports (`flowsta_hc_lines::v06::holochain_client`, `flowsta_hc_lines::v07::lair_keystore_api`, ...) rather than declaring them in your own `Cargo.toml`: two declarations of one crate at different versions cannot resolve. An app compiles at most two lines, the current one and the one before it.

## The core2 patch

`core2` 0.4.0, a dependency of the lair crates, was yanked from crates.io and its source repository archived, so a fresh dependency resolve fails without help. This repository vendors the crate. A `[patch]` does not carry through a dependency, so add the same patch to your app's `Cargo.toml`:

```toml
[patch.crates-io]
core2 = { git = "https://github.com/WeAreFlowsta/flowsta-hc-lines" }
```

Pin it with `tag = "..."` to the release of this library you depend on.

## Toolchain

The 0.7 client crates need Rust 1.93 or later; this repository pins 1.99.1 in `rust-toolchain.toml`.

## License

MIT. See [LICENSE](LICENSE).
