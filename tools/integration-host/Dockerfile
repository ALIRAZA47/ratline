# The integration host for M2 (R-01).
#
# §6.7 requires integration tests against real VMs or containers and rules out
# mocks for anything touching a host, so this is a sanctioned host rather than a
# concession. What it has to prove is narrower than "it boots":
#
#   1. SSH accepts a NON-ROOT user with sudo. That is what RL-M2-010 bootstraps
#      over, and C1 — "no root SSH to managed hosts" — is asserted against it.
#      A container that only offers a root shell would let the agent be installed
#      by a route the product forbids, and every C1 test would pass vacuously.
#
#   2. systemd answers. RL-M2-008 puts the privileged helper behind socket
#      activation, RL-M2-015 wants unattended-upgrades and RL-M2-016 manages a
#      web server service. A container with no real PID 1 cannot host any of
#      them, and finding that out at RL-M2-008 would waste everything between.
#
# Debian 12 exactly, because that is what M2's exit criteria name.
FROM debian:12

# `systemd` without `systemd-sysv`, and PID 1 is systemd's own binary rather than
# /sbin/init — that symlink is what systemd-sysv provides, so installing one
# without the other and then asking for /sbin/init fails at container start with
# "no such file or directory". dbus is required for systemctl to reach PID 1.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd dbus openssh-server sudo ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Units that cannot work in a container and would otherwise sit in a failed
# state, making `systemctl is-system-running` report degraded and any health
# assertion ambiguous.
RUN systemctl mask \
      systemd-firstboot.service \
      systemd-udevd.service \
      systemd-udev-trigger.service \
      systemd-modules-load.service \
      sys-kernel-debug.mount \
      sys-kernel-tracing.mount

# The account the control plane bootstraps THROUGH. No password: key only,
# which is what RL-M2-010 will use, and NOPASSWD sudo because bootstrap runs
# unattended.
#
# Named `deployer`, not `operator`: Debian's base-passwd already ships an
# `operator` GROUP at gid 37, so `useradd operator` fails with exit 9 and the
# obvious fix — passing `-g operator` — would quietly put the bootstrap account
# into a system group it has no business in. The kind of detail that only shows
# up against a real host, which is §6.7's argument in miniature.
RUN useradd --create-home --user-group --shell /bin/bash deployer \
 && install -d -m 0700 -o deployer -g deployer /home/deployer/.ssh \
 && echo 'deployer ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deployer \
 && chmod 0440 /etc/sudoers.d/deployer

# Root login off from the start, so C1 is the container's default rather than
# something a test has to arrange. RL-M2-029 asserts this stays true.
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && systemctl enable ssh

EXPOSE 22
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
