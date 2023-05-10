use anyhow::{anyhow, Ok};

use chacha20poly1305::{
    aead::stream,
    XChaCha20Poly1305,
    KeyInit,
};
use std::{
    fs::File,
    io::Read,
};
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);


pub trait FileEncryptor {
    fn encrypt_file(&self, dist_file_path: &str, last_file_path: &str) -> Result<(), anyhow::Error>;
    fn decrypt_large_file(&self, dist_file_path: &str, last_decry_path: &str) -> Result<(), anyhow::Error>;
}

pub struct XChaCha20Poly1305Encryptor<'a> {
    pub key: &'a [u8; 32],
    pub nonce: &'a [u8; 19],
}

impl<'a> FileEncryptor for XChaCha20Poly1305Encryptor<'a> {
    fn encrypt_file(&self, dist_file_path: &str, last_file_path: &str) -> Result<(), anyhow::Error> {
        // Create an authenticated encryption with associated data (AEAD) instance using the key.
        let aead = XChaCha20Poly1305::new(self.key.as_ref().into());
    
        // Create a stream encryptor using the AEAD instance and the nonce.
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, self.nonce.as_ref().into());
    
        // Set the size of the buffer to use when reading and encrypting the file.
        const BUFFER_LEN: usize = 500;
        let mut buffer;
    
        // Open the source file for reading.
        let mut source_file = File::open(dist_file_path)?;
    
        // Initialize an empty vector to hold the encrypted content.
        let mut content_type:Vec<u8> = [].to_vec();
    
        // Read the source file into the buffer in chunks of BUFFER_LEN bytes.
        loop {
            // Initialize the buffer with zeros.
            buffer = [0u8; BUFFER_LEN];
    
            // Read up to BUFFER_LEN bytes from the source file into the buffer.
            let read_count = match source_file.read(&mut buffer){
                std::result::Result::Ok(e) => e,
                Err(_e) => return Ok(()), // Exit the loop if an error occurs.
            };
    
            // If we read BUFFER_LEN bytes, encrypt the buffer and add the encrypted content to the result vector.
            if read_count == BUFFER_LEN {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
    
                let mut encoded_ciphertext = String::new();
                CUSTOM_ENGINE.encode_string(ciphertext, &mut encoded_ciphertext);
    
                content_type.extend(encoded_ciphertext.as_bytes());
            }
            // Otherwise, encrypt the remaining bytes and add the encrypted content to the result vector.
            else {
                if buffer.len() <= 0{
                    content_type.extend("".as_bytes());
                }
                else{
                    let ciphertext = stream_encryptor
                        .encrypt_last(&buffer[..read_count])
                        .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
    
                    let mut encoded_ciphertext = String::new();
                    CUSTOM_ENGINE.encode_string(ciphertext, &mut encoded_ciphertext);
    
                    content_type.extend(encoded_ciphertext.as_bytes());   
                }
    
                // Exit the loop.
                break;
            }
        }
        
        
                match std::fs::write(dist_file_path, content_type){ //We overwrite the normal data with the encrypted data.
                    _ => ()
                };
                match std::fs::write(last_file_path, dist_file_path.to_string()){ //Saving the last encrypted file path to log file.
                    _ => ()
                };
            
        
        Ok(())
    }



    fn decrypt_large_file(&self, dist_file_path: &str, last_decry_path: &str) -> Result<(), anyhow::Error> {
        // Initialize an AEAD encryption scheme with the provided key
        let aead = XChaCha20Poly1305::new(self.key.as_ref().into());
    
        // Initialize a stream decryptor with the provided nonce
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, self.nonce.as_ref().into());
    
        // Set the buffer length
        const BUFFER_LEN: usize = 664 + 24;
        let mut buffer;
    
        // Open the encrypted file
        let mut encrypted_file = match File::open(dist_file_path){
            std::result::Result::Ok(e) => e,
            Err(_e) => return Ok(()),
        };
    
        // Initialize an empty vector to hold the decrypted plaintext
        let mut plaintext_type:Vec<u8> = [].to_vec();
    
        // Loop through the encrypted file, decrypting each buffer of data
        loop {
            buffer = [0u8; BUFFER_LEN];
            let read_count = match encrypted_file.read(&mut buffer){
                std::result::Result::Ok(e) => e,
                Err(_e) => return Ok(()),
            };
    
            if read_count == BUFFER_LEN {
    
                // Decode the buffer using a custom decoding engine
                let mut dec_buffer = Vec::<u8>::new();
                match CUSTOM_ENGINE.decode_vec(
                    &buffer[..BUFFER_LEN],
                    &mut dec_buffer,
                ){
                    std::result::Result::Ok(e) => e,
                    Err(_e) => return Ok(()),
                };
    
                // Decrypt the decoded buffer and add it to the plaintext vector
                let plaintext = stream_decryptor
                    .decrypt_next(dec_buffer.as_slice())
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
    
                drop(dec_buffer);
                plaintext_type.extend(plaintext);
            }
    
            else {
    
                // If the buffer length is less than the expected length, decode and decrypt the remaining data
                if buffer.len() <= 0{
                    plaintext_type.extend("".as_bytes());
                }
                else {
                    let mut decoded_cleaned_buffer = Vec::<u8>::new();
                    match CUSTOM_ENGINE.decode_vec(
                        &buffer[..read_count],
                        &mut decoded_cleaned_buffer,
                    ){
                        std::result::Result::Ok(e) => e,
                        Err(_e) => return Ok(()),
                    };
    
                    let cleaned_read_count_1 = decoded_cleaned_buffer.len();
    
                    // Decrypt the remaining data and add it to the plaintext vector
                    let plaintext = stream_decryptor
                        .decrypt_last(&decoded_cleaned_buffer[..cleaned_read_count_1])
                        .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                    plaintext_type.extend(plaintext);    
                }
                
                break;
            }
        }
    
    
        match std::fs::write(dist_file_path, plaintext_type){ //We overwrite the encrypted file with the decrypted data. 
            _ => ()
        };
        
        match std::fs::write(last_decry_path, dist_file_path.to_string()){ //Saving the last decrypted file path to last_decode.tmp.
            _ => ()
        }; 

        Ok(())
    }

}