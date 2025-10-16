# Ham_Harvester
# QRZ County Ham Lookup Tool

## Overview

The **QRZ County Ham Lookup Tool** is a Python-based cross-platform application that queries **QRZ.com** for all licensed amateur radio operators (Hams) within a specified **county and state** in the United States.

It includes:
- A **GUI interface** for ease of use on Windows, macOS, and Linux.
- A **verbose mode** for detailed console output.
- An **elapsed time and ETA** progress tracker.
- Options to **export results to CSV**.
- The ability to **map licensee locations** in Google Maps or Google Earth (via KML overlay generation).

This tool is ideal for ham radio enthusiasts, club coordinators, emergency communications planners, or researchers looking to visualize call sign data geographically.

---

## Features

- 🔍 **Query QRZ.com** by county and state  
- 🖥️ **Cross-platform GUI** (runs anywhere Python and Tkinter are supported)  
- 📊 **Progress tracking** with elapsed time and estimated completion time  
- 🗂️ **Export results** to a CSV file  
- 🌍 **Google Maps / Google Earth overlay** option  
- 🧩 **Verbose mode** for debugging or detailed monitoring  

---

## Requirements

### Dependencies

- **Python 3.9+**
- The following Python libraries:
  ```bash
  pip install requests beautifulsoup4 pandas tk tqdm geopy simplekml
