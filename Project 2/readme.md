# Project 2: Basic Encryption & Decryption 🔐

**Track:** Junior Analyst // DecodeLabs Industrial Kit (Batch 2026)  
**Phase:** Cryptographic Confidentiality Logic[cite: 2]

## Overview
Welcome to Project 2 of the DecodeLabs Cybersecurity Internship. This milestone focuses on data confidentiality and cryptographic fundamentals[cite: 2]. Rather than relying on static perimeters, information in motion requires mathematical transformation to remain unreadable to unauthorized observers[cite: 2].

<img width="1918" height="911" alt="Screenshot_2026-09-01_12_44_25" src="https://github.com/user-attachments/assets/01c0d4c3-1049-4438-85c1-c87cbcd82938" />


## Key Requirements & Features
- **Caesar Cipher Mechanism:** Implements mono-alphabetic substitution using numerical shifts[cite: 2].
- **Modular Arithmetic ($% 26$):** Manages finite alphabet wrapping seamlessly without index out-of-range errors[cite: 2].
- **Edge Case Handling:** Preserves spaces, digits, and punctuation symbols while shifting alphabetical characters.
- **Symmetric Reversibility:** Features standalone encryption and decryption functions using the `ord()` and `chr()` built-in utilities[cite: 2].

## Technical Implementation
- **Language:** Python 3[cite: 2]
- **Mathematical Model:** $E_n(x) = (x + n) \% 26$ and $D_n(x) = (x - n) \% 26$[cite: 2]

## Usage Instructions
1. Run the script in your terminal:
   ```bash
   python3 caesar_cipher.py
