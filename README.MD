syslog_simulator.py
Simulate a Linux device producing real-time syslog messages with a fixed hostname.
- Outputs RFC3164-like syslog lines to stdout and/or sends to a syslog server via UDP/TCP.
- Content is randomized but plausible (sshd, sudo, cron, systemd, kernel, nginx, etc.)

Examples:
  # 1) Print to stdout (pipe to whatever)
  python3 syslog_simulator.py --hostname web-01 --stdout

  # 2) Send UDP to a syslog receiver (e.g., rsyslog on 192.168.1.10:514)
  python3 syslog_simulator.py --hostname db-01 --udp 192.168.1.10:514

  # 3) Send TCP + also stdout, 5-12 msgs/sec
  python3 syslog_simulator.py --hostname app-01 --tcp 127.0.0.1:514 --rate 5:12 --stdout:wq