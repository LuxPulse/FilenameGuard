use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use chrono::Utc;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::fs;
use std::env;
use std::path::{Path, PathBuf};
use std::io::{Write, Read};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

// Cryptographic parameters
const SALT_LENGTH: usize = 16;
const IV_LENGTH: usize = 16;
const HMAC_LENGTH: usize = 32;
const PBKDF2_ITERATIONS: u32 = 600_000;
const MIN_PASSWORD_LENGTH: usize = 12;

// Password complexity requirements
const MIN_UPPERCASE: usize = 1;
const MIN_LOWERCASE: usize = 1;
const MIN_DIGITS: usize = 1;
const MIN_SPECIAL: usize = 1;
const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key
    );
    key
}

fn check_password_complexity(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(format!(
            "Password must be at least {} characters", 
            MIN_PASSWORD_LENGTH
        ));
    }

    let mut uppercase = 0;
    let mut lowercase = 0;
    let mut digits = 0;
    let mut special = 0;

    for c in password.chars() {
        if c.is_ascii_uppercase() {
            uppercase += 1;
        } else if c.is_ascii_lowercase() {
            lowercase += 1;
        } else if c.is_ascii_digit() {
            digits += 1;
        } else if SPECIAL_CHARS.contains(c) {
            special += 1;
        }
    }

    let mut errors = Vec::new();

    if uppercase < MIN_UPPERCASE {
        errors.push(format!("at least {} uppercase letter", MIN_UPPERCASE));
    }
    if lowercase < MIN_LOWERCASE {
        errors.push(format!("at least {} lowercase letter", MIN_LOWERCASE));
    }
    if digits < MIN_DIGITS {
        errors.push(format!("at least {} digit", MIN_DIGITS));
    }
    if special < MIN_SPECIAL {
        errors.push(format!("at least {} special character", MIN_SPECIAL));
    }

    if !errors.is_empty() {
        return Err(format!(
            "Password must contain: {}",
            errors.join(", ")
        ));
    }

    Ok(())
}

fn check_file_permissions(path: &Path, write: bool) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to access file metadata: {}", e))?;
    
    if metadata.permissions().readonly() && write {
        return Err("File is read-only".to_string());
    }
    
    // Attempt to open file in required mode
    if write {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("Write permission denied: {}", e))?;
    } else {
        fs::File::open(path)
            .map_err(|e| format!("Read permission denied: {}", e))?;
    }
    
    Ok(())
}

fn encrypt_file(path: &str, password: &str) -> Result<(), String> {
    // Validate password complexity
    check_password_complexity(password)?;
    
    let path_obj = Path::new(path);
    
    // File validation
    if !path_obj.exists() {
        return Err(format!("File not found: {}", path));
    }
    if path_obj.is_dir() {
        return Err(format!("Path is a directory: {}", path));
    }
    
    // Check read permissions
    check_file_permissions(path_obj, false)?;

    let filename = path_obj.file_name()
        .ok_or("Invalid filename")?
        .to_str()
        .ok_or("Filename contains invalid UTF-8 characters")?;

    // Generate cryptographically secure salt and IV
    let mut salt = [0u8; SALT_LENGTH];
    let mut iv = [0u8; IV_LENGTH];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    // Derive encryption key
    let key = derive_key(password, &salt);

    // Read file data
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Encrypt data
    let cipher = Aes256Cbc::new_from_slices(&key, &iv)
        .map_err(|_| "Invalid key/IV length".to_string())?;
    let ciphertext = cipher.encrypt_vec(&data);

    // Generate HMAC for authentication
    let mut hmac = HmacSha256::new_from_slice(&key)
        .map_err(|_| "Invalid key length for HMAC".to_string())?;
    hmac.update(&salt);
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let hmac_result = hmac.finalize().into_bytes();

    // Create output file
    let output_path = format!("{}.enc", path);
    let output_path_obj = Path::new(&output_path);
    
    // Check if output file exists
    if output_path_obj.exists() {
        return Err(format!("Output file already exists: {}", output_path));
    }
    
    // Check write permissions for output directory
    if let Some(parent) = output_path_obj.parent() {
        check_file_permissions(parent, true)?;
    }

    let mut output = fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    // Write security components
    output.write_all(&salt)
        .and_then(|_| output.write_all(&iv))
        .and_then(|_| output.write_all(&ciphertext))
        .and_then(|_| output.write_all(&hmac_result))
        .map_err(|e| format!("Write operation failed: {}", e))?;

    println!("✅ File encrypted successfully: {}", output_path);
    println!("🔒 Security components: Salt ({} bytes), IV ({} bytes), HMAC ({} bytes)", 
             SALT_LENGTH, IV_LENGTH, HMAC_LENGTH);
    Ok(())
}

fn decrypt_file(path: &str, password: &str) -> Result<(), String> {
    let path_obj = Path::new(path);
    
    // Input validation
    if !path_obj.exists() {
        return Err(format!("File not found: {}", path));
    }
    if path_obj.is_dir() {
        return Err(format!("Path is a directory: {}", path));
    }
    
    // Check read permissions
    check_file_permissions(path_obj, false)?;

    // Get base filename
    let base_filename = path_obj.file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Could not determine base filename")?;
    
    // Generate timestamped output filename
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let output_filename = format!("{}_{}", base_filename, timestamp);
    let output_path = PathBuf::from(&output_filename);
    
    // Check if output file exists (unlikely but possible)
    if output_path.exists() {
        return Err(format!(
            "Output file '{}' already exists", 
            output_filename
        ));
    }
    
    // Check write permissions for output directory
    if let Some(parent) = output_path.parent() {
        check_file_permissions(parent, true)?;
    }

    // Read encrypted data
    let mut encrypted_data = Vec::new();
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    file.read_to_end(&mut encrypted_data)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    // Verify file length
    if encrypted_data.len() < SALT_LENGTH + IV_LENGTH + HMAC_LENGTH {
        return Err("File is too small to contain valid encrypted data".to_string());
    }

    // Parse security components
    let salt = &encrypted_data[..SALT_LENGTH];
    let iv = &encrypted_data[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
    let hmac_start = encrypted_data.len() - HMAC_LENGTH;
    let (ciphertext, expected_hmac) = encrypted_data.split_at(hmac_start);
    let ciphertext = &ciphertext[SALT_LENGTH + IV_LENGTH..];

    // Derive key from password and salt
    let key = derive_key(password, salt);

    // Verify HMAC authentication
    let mut hmac = HmacSha256::new_from_slice(&key)
        .map_err(|_| "Invalid key length".to_string())?;
    hmac.update(salt);
    hmac.update(iv);
    hmac.update(ciphertext);
    
    if hmac.verify_slice(expected_hmac).is_err() {
        return Err("Decryption failed: Incorrect password or corrupted file".to_string());
    }

    // Decrypt data
    let cipher = Aes256Cbc::new_from_slices(&key, iv)
        .map_err(|_| "Invalid key/IV length".to_string())?;
    
    let plaintext = cipher.decrypt_vec(ciphertext)
        .map_err(|e| format!("Decryption process failed: {}", e))?;

    // Write decrypted file
    fs::write(&output_path, &plaintext)
        .map_err(|e| format!("Failed to write decrypted file: {}", e))?;

    println!("✅ Decryption successful! File saved as: {}", output_path.display());
    println!("🔓 Security verification: HMAC validated, data integrity confirmed");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let program_name = args.get(0).map(|s| {
        Path::new(s).file_name().and_then(|n| n.to_str()).unwrap_or("fileguard")
    }).unwrap_or("fileguard");
    
    if args.len() < 4 {
        eprintln!(
            "FileGuard - Military-Grade File Encryption\n\n\
            Usage:\n  {0} encrypt <file_path> <password>\n  {0} decrypt <file_path.enc> <password>\n\n\
            Examples:\n  {0} encrypt document.txt \"StrongP@ssw0rd!\"\n  {0} decrypt document.txt.enc \"StrongP@ssw0rd!\"\n\n\
            Security Features:\n  - AES-256-CBC encryption with PBKDF2 key derivation\n  - HMAC-SHA256 integrity protection\n  - Unique salt and IV per file\n  - 600,000 PBKDF2 iterations\n\n\
            Password Requirements:\n  - Minimum {1} characters\n  - At least {2} uppercase letter\n  - At least {3} lowercase letter\n  - At least {4} digit\n  - At least {5} special character ({6})",
            program_name, 
            MIN_PASSWORD_LENGTH,
            MIN_UPPERCASE,
            MIN_LOWERCASE,
            MIN_DIGITS,
            MIN_SPECIAL,
            SPECIAL_CHARS
        );
        return;
    }

    let result = match args[1].as_str() {
        "encrypt" => encrypt_file(&args[2], &args[3]),
        "decrypt" => decrypt_file(&args[2], &args[3]),
        _ => Err(format!("Unknown command: {}", args[1])),
    };

    if let Err(e) = result {
        eprintln!("❌ Operation failed: {}", e);
        eprintln!("💡 Troubleshooting tips:");
        eprintln!("   - Verify password meets complexity requirements");
        eprintln!("   - Check file permissions and existence");
        eprintln!("   - Ensure sufficient disk space is available");
        eprintln!("   - Confirm encrypted files have .enc extension");
        std::process::exit(1);
    }
}