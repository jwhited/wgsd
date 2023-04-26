# wgsd-client systemd Integration

systemd timers can be used to periodically invoke `wgsd-client`.

## Installation

* Copy `wgsd-client@.service` to `/etc/systemd/system/`.
* Copy `wgsd-client@.timer`  to `/etc/systemd/system/`.

## Configuration

* To configure `wgsd-client` for WireGuard interface `wg-foo` copy `wg-example.template.env` to `/etc/wgsd/wg-foo.env` and adjust variables accordingly.

## Activation

* To activate periodic `wgsd-client` invocation for WireGuard interface `wg-foo` run `systemctl enable wgsd-client@wg-foo.timer`.
