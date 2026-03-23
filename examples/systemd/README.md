## Systemd Unit Examples

The directory lists some systemd unit files for example, which can be used to run `chagle` as a service on Linux.

[The `@` symbol in the name of unit files](https://superuser.com/questions/393423/the-symbol-and-systemctl-and-vsftpd) such as
`chagle@.service` facilitates the management of multiple instances of `chagle`.

For the naming of the example, `chagles` stands for `chagle --server`, and `chaglec` stands for `chagle --client`, `chagle` is just `chagle`.

For security, it is suggested to store configuration files with permission `600`, that is, only the owner can read the file, preventing arbitrary users on the system from accessing the secret tokens.

### With root privilege

Assuming that `chagle` is installed in `/usr/bin/chagle`, and the configuration file is in `/etc/chagle/app1.toml`, the following steps show how to run an instance of `chagle --server` with root.

1. Create a service file.

```bash
sudo cp chagles@.service /etc/systemd/system/
```

2. Create the configuration file `app1.toml`.

```bash
sudo mkdir -p /etc/chagle
# And create the configuration file named `app1.toml` inside /etc/chagle
```

3. Enable and start the service.

```bash
sudo systemctl daemon-reload # Make sure systemd find the new unit
sudo systemctl enable chagles@app1 --now
```

### Without root privilege

Assuming that `chagle` is installed in `~/.local/bin/chagle`, and the configuration file is in `~/.local/etc/chagle/app1.toml`, the following steps show how to run an instance of `chagle --server` without root.

1. Edit the example service file as...

```txt
# with root
# ExecStart=/usr/bin/chagle -s /etc/chagle/%i.toml
# without root
ExecStart=%h/.local/bin/chagle -s %h/.local/etc/chagle/%i.toml
```

2. Create a service file.

```bash
mkdir -p ~/.config/systemd/user
cp chagles@.service ~/.config/systemd/user/
```

3. Create the configuration file `app1.toml`.

```bash
mkdir -p ~/.local/etc/chagle
# And create the configuration file named `app1.toml` inside ~/.local/etc/chagle
```

4. Enable and start the service.

```bash
systemctl --user daemon-reload # Make sure systemd find the new unit
systemctl --user enable chagles@app1 --now
```

### Run multiple services

To run multiple services at once, simply add another configuration, say `app2.toml` under `/etc/chagle` (`~/.local/etc/chagle` for non-root), then run `sudo systemctl enable chagles@app2 --now` (`systemctl --user enable chagles@app2 --now` for non-root) to start an instance for that configuration.

The same applies to `chaglec@.service` for `chagle --client` and `chagle@.service` for `chagle`.
