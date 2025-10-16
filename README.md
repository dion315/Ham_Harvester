# Ham_Harvester
# QRZ County Ham Lookup Tool

## Overview

The **QRZ County Ham Lookup Tool** is a Python-based, cross-platform utility that retrieves licensed amateur radio operators (Hams) registered on **QRZ.com** for a specified **county and state** in the U.S.  

It’s designed for ease of use, flexibility, and portability — whether you’re a club coordinator, emergency communications planner, or ham enthusiast mapping local operators.

The tool now supports:
- Automatic **dependency checking and installation**
- Optional use of your **QRZ XML API key** for authenticated lookups
- A **GUI interface** that runs on any platform
- **CSV export**
- **Interactive HTML map export**
- **Verbose mode** for detailed execution logging
- **Elapsed time and ETA tracking**

---

## Features

| Feature | Description |
|----------|--------------|
| 🧰 **Automatic Dependency Management** | Ensures all required Python packages are installed before execution |
| 🔍 **QRZ.com Query** | Searches licensed operators by state and county |
| 🔑 **API Integration** | Supports QRZ XML Subscription API key for higher reliability and no scraping |
| 🖥️ **Cross-Platform GUI** | Works on Windows, macOS, and Linux |
| 📊 **Progress and ETA Tracking** | Displays time elapsed and estimated completion |
| 🗂️ **CSV Export** | Saves results locally for data analysis |
| 🌍 **Interactive Map Export** | Generates a shareable HTML map using Google Maps or Leaflet |
| 🧩 **Verbose Mode** | Displays detailed execution steps for debugging or transparency |

---

## Requirements

### Python Version
- **Python 3.9+** required

### Dependencies
The script automatically checks for and installs missing modules on startup.  
If needed, you can manually install dependencies with:

```bash
pip install requests pandas tk geopy geojson
