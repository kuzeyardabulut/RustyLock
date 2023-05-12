# Rust-based Ransomware
This Windows ransomware example is written in 100% Rust. This code encrypts all files that the computer can read and write under the User directory.


## How to Use
To use the ransomware, you will need to compile it from the source. Here are the steps to do so:

1. Clone the repository to your local machine: `git clone https://github.com/kuzeyardabulut/RustyLock.git`

2. Install Rust on your machine if you haven't already. You can download Rust from the official website: https://www.rust-lang.org/tools/install

3. Navigate to the project directory and compile the code:
```bash
cd RustyLock
cargo build --release
```

4. Once the code is compiled, you can run the ransomware:
`./target/release/inject.exe`

5. The ransomware will encrypt all files in the User directory and its subdirectories with the AES algorithm.


## Working Flow
This ransomware has been designed to encrypt files on a user's system and demand a ransom for their release. Here's how it works:

1. Upon execution, the ransomware copies itself to the startup folder to ensure persistence across reboots.
2. It then scans the user's directory and subdirectory for files that have read-write permissions and creates a list of these files, which it saves in the /tmp/ directory. The ransomware then waits for the next startup.
3. During the next startup, the ransomware reads the list of files saved in the /tmp/ folder and begins encrypting them. Even if the system is turned off during this process, no data loss will occur. When the system is turned back on, the ransomware will resume the encryption process from where it left off.
4. Once the encryption process is complete, the ransomware creates a file named **encoded.txt** and awaits the next startup.
5. During the next startup, the ransomware detects the **encoded.txt** file and begins to decrypt the system. Again, even if the system is turned off during this process, no data loss will occur.
6. Once all decryption processes are complete, the ransomware and its traces are deleted to avoid detection.


## How it Works?
Upon opening the .exe file, the program first runs the anti-debugger and check_process functions. If these anti-reversing functions are passed without error, an incognito window is created. In this window, the path of the current location of the .exe file is retrieved, and the file is copied to ``\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup``. The .dll file in the same directory is also copied to the ``\AppData\Local\Programs\Microsoft Store`` folder. Essentially, this adds the .exe to the startup scripts of Windows, ensuring that the file runs each time the computer is turned on.

Running a .exe in startup scripts is not always advisable. Therefore, you can do some configuration for regedit, enabling the .exe to be run in the same way as startup scripts. However, to add configuration to regedit, the user must run the .exe as an administrator.

Following these steps, the ransomware's .dll file is injected into ``SecurityHealthSystray`` using the ``dll_syringe`` library. The .dll file activates many security functions, most of which are sourced from [here](https://chuongdong.com/malware%20development/2020/06/09/rust-ransomware1/). These anti-reversing functions are performed for a while and the program waits for their completion. If no issues are found during the check, the ransomware is launched.

Initially, AES keys are defined. In real examples, keys are randomly generated and transmitted to the server side over the internet. Every time the program is opened and closed, the program communicates with the server side with certain security measures until the encryption is complete. All key exchanges on the server side and client side are conducted in an asymmetric encrypted manner, making it impossible to reverse engineer and find the key.

Once the keys are created, directories are defined and the program starts. It first checks whether the system has been encrypted before by examining the ``\AppData\Local\Temp\encoded.txt`` file (in real examples, this is usually done by communicating with the APIs). If the system has been encrypted before, the program decrypts it using the **decrypt_large_file** function. Otherwise, the **encrypt_file** function is called to initiate the encryption.

When these functions are called, the program checks whether the target function has previously been executed. If so, it resumes from where it left off; otherwise, it starts the target function from the beginning.


## Disclaimer
This ransomware is for educational purposes only. Please do not use it for any malicious activities. The author is not responsible for any damages or legal issues caused by the misuse of this code.


## License
This code is licensed under the MIT License. Please see the [LICENSE](https://github.com/kuzeyardabulut/RustyLock/blob/main/LICENSE) file for more details.


## Contributions
Contributions are welcome! If you find any bugs or have any suggestions for improvement, please create a pull request.
