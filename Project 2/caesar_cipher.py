def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypts plaintext using a Caesar Cipher shift with modular arithmetic."""
    encrypted_text = ""
    for char in text:
        if char.isupper():
            # Base 'A' is 65; apply shift and wrap around using % 26
            encrypted_text += chr((ord(char) - 65 + shift) % 26 + 65)
        elif char.islower():
            # Base 'a' is 97; apply shift and wrap around using % 26
            encrypted_text += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            # Preserve spaces, numbers, and punctuation edge cases
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypts ciphertext by reversing the Caesar Cipher shift."""
    decrypted_text = ""
    for char in text:
        if char.isupper():
            decrypted_text += chr((ord(char) - 65 - shift) % 26 + 65)
        elif char.islower():
            decrypted_text += chr((ord(char) - 97 - shift) % 26 + 97)
        else:
            decrypted_text += char
    return decrypted_text

def main():
    print("=" * 55)
    print("  DecodeLabs: Project 2 - Basic Encryption & Decryption")
    print("=" * 55)
    
    while True:
        choice = input("\n[1] Encrypt Text (Plaintext -> Ciphertext)\n[2] Decrypt Text (Ciphertext -> Plaintext)\n[3] Exit\nSelect an option: ").strip()
        
        if choice == '1':
            plaintext = input("Enter plaintext message: ")
            try:
                shift = int(input("Enter shift key (integer): "))
            except ValueError:
                print("[!] Invalid shift key. Please enter a whole number.")
                continue
            
            ciphertext = caesar_encrypt(plaintext, shift)
            print(f"[*] Ciphertext Output: {ciphertext}")
            
        elif choice == '2':
            ciphertext = input("Enter ciphertext message: ")
            try:
                shift = int(input("Enter shift key (integer): "))
            except ValueError:
                print("[!] Invalid shift key. Please enter a whole number.")
                continue
            
            plaintext = caesar_decrypt(ciphertext, shift)
            print(f"[*] Decrypted Plaintext: {plaintext}")
            
        elif choice == '3':
            print("[*] Exiting cryptographic module. Secure your transmission channels!")
            break
        else:
            print("[!] Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
