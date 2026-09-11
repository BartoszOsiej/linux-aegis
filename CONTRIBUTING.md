# Contributing

Thanks for considering a contribution to AEGIS. This is a kernel-module project:
changes get extra scrutiny, so write for reviewers.

## Ground rules

- One logical change per PR; a PR must build and pass CI.
- Reference the issue: `Fixes #123`.
- Keep the diff small and focused on the in-tree `aegis/` module or `devkit/`.
- Do not reformat unrelated code.

## Dev setup

```bash
git clone https://github.com/BartoszOsiej/linux-aegis
cd linux-aegis
```

Build the userspace devkit (aegisctl + initramfs):

```bash
cd devkit
make -j"$(nproc)" initramfs
file devkit/build/aegisctl
devkit/build/aegisctl help
```

The full in-tree module build fetches upstream `torvalds/linux`, applies the
patches in `patches/`, configures with `build/aegis.config` and compiles
`security/aegis/`. It runs in CI; you do not need a kernel tree locally unless
you change the module itself — in that case the CI build is the gate.

## Commit style

`type(scope): summary` — `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.
For kernel patches favour the kernel's own conventions
(`aegis: security: <summary>`).

## Security

AEGIS is a security module. Report vulnerabilities privately to
`thethreadcalls@outlook.com` — do not open a public issue for them. Include the
kernel version, the AEGIS build configuration, and a reproducer if possible.

## License

`COPYING` is GPL-2.0. By contributing you agree your changes are licensed
under GPL-2.0.