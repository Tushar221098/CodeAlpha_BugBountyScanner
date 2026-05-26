# CodeAlpha Bug Bounty Scanner

## Project Overview

This project was created as part of my CodeAlpha Cyber Security Internship task.

The Simple Bug Bounty Scanner is a beginner-friendly Python static code analysis tool. It scans a project folder and checks source code files for common security risks such as hardcoded passwords, API keys, secrets, insecure HTTP links, debug mode, and weak MD5 hashing.

## Objective

The objective of this project is to understand how basic vulnerability scanning works and how security tools can identify risky coding patterns before code is deployed.

## Features

- Scans a full folder
- Checks selected file types such as `.py`, `.js`, `.txt`, `.env`, and `.json`
- Skips unnecessary folders such as `venv`, `.git`, `__pycache__`, and `node_modules`
- Detects common risky patterns:
  - Hardcoded passwords
  - API keys
  - Secret keys
  - Insecure HTTP links
  - Debug mode enabled
  - Weak MD5 hash usage
- Shows file name, line number, severity, issue type, and matching code
- Prints a severity summary with HIGH, MEDIUM, and LOW findings

## Technologies Used

- Python
- File handling
- Loops
- Conditional statements
- Basic static code analysis
- OS module

## How It Works

The scanner uses Python's `os.walk()` function to go through a folder and its subfolders. It checks only allowed file types and skips unnecessary directories to improve scanning speed.

Each file is opened and read line by line. The scanner checks each line for risky keywords or patterns. If a match is found, the tool stores the finding and prints it in a final report.

## How to Run

1. Clone this repository:

```bash
git clone https://github.com/YOUR-USERNAME/CodeAlpha_BugBountyScanner.git