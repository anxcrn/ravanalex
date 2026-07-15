---
name: hardware-and-rf-hacking
description: The methodology for hacking physical hardware interfaces (UART, JTAG, SPI) and Radio Frequency communications (SDR, RFID, BLE).
---

# 📻 Hardware & RF Hacking (The Physical Layer)

This skill is for interacting directly with the physical components of a device or the invisible radio waves it uses to communicate.

## PHASE 1: HARDWARE INTERFACES (The Holy Trinity)

When you open a device, look for exposed pins or pads on the PCB.

### 1. UART (Universal Asynchronous Receiver-Transmitter)
UART is the serial console. It's often left active by developers for debugging. If you find it, you might get a root shell just by plugging in.
- **Identify:** Look for 3 or 4 pins grouped together (TX, RX, GND, VCC).
- **Tool:** A USB-to-TTL serial adapter (e.g., CP2102, FT232).
- **Method:**
  1. Find Ground (GND) with a multimeter (continuity mode to a metal shield).
  2. Find Transmit (TX) by measuring voltage (usually 3.3V that fluctuates when the device boots).
  3. Connect USB adapter RX to device TX, adapter TX to device RX.
  4. Use `minicom` or `screen` or `putty` to connect. You must guess the baud rate (usually `115200` or `9600`).
  ```bash
  screen /dev/ttyUSB0 115200
  ```

### 2. SPI (Serial Peripheral Interface)
SPI is commonly used to connect the main processor to the flash memory chip (where the firmware and filesystem live).
- **Goal:** Read the firmware directly off the chip, bypassing any software locks.
- **Identify:** Look for an 8-pin or 16-pin SOIC chip (Winbond, Macronix).
- **Tool:** A flash programmer like the CH341A or a Bus Pirate.
- **Method:**
  Use `flashrom` on your PC to read the chip.
  ```bash
  flashrom -p ch341a_spi -r firmware_dump.bin
  ```
  Once you have `firmware_dump.bin`, use `binwalk` (See `iot-and-scada-exploitation`).

### 3. JTAG (Joint Test Action Group)
JTAG is a hardware debugging protocol. It allows you to pause the CPU, read/write memory, and step through instructions at the hardware level.
- **Identify:** Look for a group of 5+ pins (TDI, TDO, TCK, TMS, GND).
- **Tool:** JTAGulator (to find the pinout) and a JTAG adapter (J-Link, Bus Pirate).
- **Method:** Use OpenOCD (Open On-Chip Debugger) to interface with the chip and extract memory or bypass security checks.

---

## PHASE 2: RADIO FREQUENCY (SDR, RFID, BLE)

If it broadcasts, it can be intercepted, replayed, or spoofed.

### 1. Sub-GHz Replay (Garage Doors, Car Fobs, Gates)
Many older wireless systems operate around 433 MHz or 315 MHz and lack rolling codes.
- **Tool:** Software Defined Radio (SDR) like the HackRF, RTL-SDR, or a Flipper Zero.
- **Method:**
  1. Record the signal when the legitimate user presses the button (e.g., using Universal Radio Hacker - URH).
  2. Replay the exact same signal. If the system lacks rolling codes, it will open.
  3. If rolling codes are present (e.g., KeeLoq), you need a RollJam attack (jamming the receiver while recording the codes, then replaying a valid future code).

### 2. RFID & NFC Cloning (Access Cards)
- **Low Frequency (125 kHz):** Old proximity cards (HID Prox). Trivial to clone.
  - **Tool:** Proxmark3.
  - **Command:** `lf search` then `lf hid clone <id>`.
- **High Frequency (13.56 MHz):** Mifare Classic (often used in hotels/offices).
  - Uses crypto, but the crypto is broken.
  - **Tool:** Proxmark3.
  - **Command:** `hf mf autopwn` (runs dictionary attacks and nested authentication attacks to extract all keys and dump the card).

### 3. Bluetooth Low Energy (BLE)
BLE is used in smart locks, health trackers, and IoT devices.
- **Tool:** `hcitool`, `gatttool`, or the `bleah` Python tool, Bettercap.
- **Method:**
  1. Discover devices: `sudo hcitool lescan`
  2. Connect to the device and enumerate its GATT characteristics (the services it offers).
  3. Read/Write to the characteristics to control the device or extract data. (Many BLE devices lack pairing authentication).
