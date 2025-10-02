# Packet Visualizer

A simple C++ packet sniffer and traffic visualizer built with [libtins](https://libtins.github.io/).  
Currently at **Milestone 2**: aggregate packet and byte counts by destination IP, updating every few seconds.

---

## Features (Milestone 2)

- Captures IP traffic on a chosen network interface.
- Runs in promiscuous mode for broader visibility.
- Aggregates **packets and bytes per destination IP**.
- Displays a refreshed summary table every 1 seconds.

---

## Requirements

- C++23
- [libtins](https://github.com/mfontanini/libtins)
- [libpcap](https://www.tcpdump.org/)
- `pkg-config`
- Linux (sniffing requires root or special capabilities)

On Ubuntu/Debian:

```bash
sudo apt install libtins-dev libpcap-dev pkg-config

```

---

## Building

1. Clone the repository:

```bash
git clone https://github.com/ChronoInferna/packetVisualizer.git
```

2. Navigate to the project directory and create a build directory:

```bash
mkdir build && cd build
cmake ..
```

3. Build the project:

```bash
cmake --build .
```

---

## Running

Run the program with root privileges to allow packet capturing:

```bash
sudo ./packetVisualizer
```

---

## Roadmap

- Milestone 3: ncurses-based live table (like iftop)

- Milestone 4: sorting and highlighting heavy talkers

- Milestone 5: optional CSV/JSON export for later analysis
