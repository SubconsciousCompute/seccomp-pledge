use optional_field::{serde_optional_fields, Field};
use seccompiler::BpfMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::metadata;
use std::fs::File;
use std::io;
use std::io::Write;
use std::process::{Command,exit};
use std::str;
use std::os::unix::net::{UnixStream,UnixListener};
use std::io::{BufRead, BufReader};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ArgsList {
    index: u32,
    r#type: String,
    op: String,
    val: u32,
    comment: Field<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LurkList {
    syscall: String,
    args: Vec<String>,
}

#[serde_optional_fields]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyscallList {
    syscall: String,
    args: Field<Vec<ArgsList>>,
}

#[derive(Debug, Serialize, Clone)]
pub struct FilterList {
    mismatch_action: String,
    match_action: String,
    filter: Vec<SyscallList>,
}

pub const OS: &str = env::consts::OS;

// Seccomp-bpf filtering
pub fn seccomp(application_name: &String, application_args: &Vec<String>, stream: Option<&UnixStream>) {
    let mut filters: HashMap<String, FilterList> = HashMap::new();
    let mut filter_name: String = String::new();
    let mut match_action: String;
    let mut mismatch_action: String;
    let mut args_list: Vec<ArgsList> = Vec::new();
    let mut number_of_filters: String = String::new();

    // Filtering begins
    println!("\n***Seccomp-BPF Filtering***\n");

    let text = "\nHow many filters do you want to construct for the process? ";

    if let Some(stream) = stream { write(stream, text); } else {
            print!("{text}");
            flush();
    };

    if let Some(stream) = stream { number_of_filters = read(stream); } else if io::stdin().read_line(&mut number_of_filters).is_err() {
        eprintln!("\nError: Failed to read input");
        exit(1);
    };

    let number_of_filters: u32 = if let Ok(number) = number_of_filters.trim().parse() {
        number
    } else {
        eprintln!("\nError: Not a number");
        exit(1);
    };

    println!("\nHere is a list of syscalls (with name and arguments) spawned by the process:\n");

    // Retrieve the list of syscalls spawned by the process along with the arguments for each
    let syscall_list: Vec<LurkList> = get_syscall_list(application_name, application_args);
    let mut filtered_syscall_list: Vec<SyscallList> = Vec::new();

    // Display the list of syscalls (name and arguments) spawned by process
    for syscall in syscall_list {
        println!("\nsyscall: {}", syscall.syscall);
        for (index, argument) in syscall.args.iter().enumerate() {
            println!("argument {}: {}", &index, &argument);
        }
    }

    for i in 0..number_of_filters {
        println!("\nCreating filter {}...", i + 1);
        let text = "\nEnter a name for this filter: ";
        if let Some(stream) = stream { write(stream, text); } else {
                print!("{text}");
                flush();
        };
        let mut input = String::new();
        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            exit(1);
        };
        filter_name = input.chars().filter(|c| !c.is_whitespace()).collect();
        let text = "\nArguments distinguish between syscalls of the same name. How many syscalls will be passed to the seccomp filter? ";
        if let Some(stream) = stream { write(stream, text); } else {
                print!("{text}");
                flush();
        };
        input = String::new();
        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            exit(1);
        };
        let count = if let Ok(number) = input.trim().parse() {
            number
        } else {
            eprintln!("\nError: Not a number");
            exit(1);
        };
        println!("\nYou can choose to construct a universal rule for the syscall that will be applied regardless of arguments");
        println!("\nYou can also choose to pattern-match specific arguments of the syscall.");
        for _ in 0..count {
            // Provide a choice for specifying a syscall without arguments or pattern-matching
            // arguments of some syscall
            let text = "\nDo you want to create a universal rule for the syscall? [y/N] ";
            if let Some(stream) = stream { write(stream, text); } else {
                    print!("{text}");
                    flush();
            };
            let mut input: String = String::new();
            if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                eprintln!("\nError: Unable to read input");
                exit(1);
            };
            match input.trim() {
                // Universal rule for some syscall
                "y" | "Y" => {
                    println!("\nConstructing a universal rule...");
                    let text = "\nEnter the name of the syscall: ";
                    if let Some(stream) = stream { write(stream, text); } else {
                            print!("{text}");
                            flush();
                    };
                    let mut input = String::new();
                    if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("\nError: Unable to read input");
                        exit(1);
                    };
                    let syscall: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                    filtered_syscall_list.push(SyscallList {
                        syscall: syscall.clone(),
                        args: Field::Missing,
                    });
                }
                // Pattern-matching syscall args
                "n" | "N" | "" => {
                    let mut input = String::new();
                    println!("\nConstructing a specific rule...");
                    let text = "\nEnter the name of the syscall: ";
                    if let Some(stream) = stream { write(stream, text); } else {
                            print!("{text}");
                            flush();
                    };
                    if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("\nError: Unable to read input");
                        exit(1);
                    };
                    let syscall: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                    input = String::new();
                    let text = "\nHow many arguments do you want to pattern-match? ";
                    if let Some(stream) = stream { write(stream, text); } else {
                            print!("{text}");
                            flush();
                    };
                    if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("\nError: Unable to read input");
                        exit(1);
                    };
                    let number_of_args = if let Ok(number) = input.trim().parse() {
                        number
                    } else {
                        eprintln!("\nError: Not a number");
                        exit(1);
                    };
                    for j in 0..number_of_args {
                        let mut input = String::new();
                        println!("\nPattern-matching argument {}...", j + 1);
                        let text = "\nEnter the index of the argument as per the syscall definition: ";
                        if let Some(stream) = stream { write(stream, text); } else {
                                print!("{text}");
                                flush();
                        };
                        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            exit(1);
                        };
                        let index = if let Ok(number) = input.trim().parse() {
                            number
                        } else {
                            eprintln!("\nError: Not a number");
                            exit(1);
                        };
                        input = String::new();
                        // Provide a list of possible values for the comparison operator
                        let text ="\nEnter the comparison operator (\"eq\" for \"equal to\", \"ne\" for \"not equal to\", \"lt\" for \"less than\", \"le\" for \"less than or equal to\", \"gt\" for \"greater than\", \"ge\" for \"greater than or equal to\", \"masked_eq\" for masked equality): ";
                        if let Some(stream) = stream { write(stream, text); } else {
                                print!("{text}");
                                flush();
                        };
                        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            exit(1);
                        };
                        let op: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                        input = String::new();
                        // Provide a list of possible values for the argument size
                        let text = "\nEnter the argument size (dword = 4 bytes, qword = 8 bytes): ";
                        if let Some(stream) = stream { write(stream, text); } else {
                                print!("{text}");
                                flush();
                        };
                        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            exit(1);
                        };
                        let r#type: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                        input = String::new();
                        let text = "\nEnter the value to be checked against: ";
                        if let Some(stream) = stream { write(stream, text); } else {
                                print!("{text}");
                                flush();
                        };
                        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            exit(1);
                        };
                        let val = if let Ok(number) = input.trim().parse() {
                            number
                        } else {
                            eprintln!("\nError: Not a number");
                            exit(1);
                        };
                        input = String::new();
                        // Providing comments is made optional by seccompiler since it is primarily
                        // for reference
                        let text = "\nDo you wish to provide an optional comment to provide meaning to each numeric value? [y/N] ";
                        if let Some(stream) = stream { write(stream, text); } else {
                                print!("{text}");
                                flush();
                        };
                        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            exit(1);
                        };
                        match input.trim() {
                            // Provide comments for syscall args
                            "y" | "Y" => {
                                let mut input: String = String::new();
                                let text = "\nEnter the comment: ";
                                if let Some(stream) = stream { write(stream, text); } else {
                                        print!("{text}");
                                        flush();
                                };
                                if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                                    eprintln!("\nError: Unable to read input");
                                    exit(1);
                                };
                                let comment = input.
                                    chars()
                                    .filter(|c| !c.is_whitespace())
                                    .collect();
                                args_list.push(ArgsList {
                                    index,
                                    op,
                                    r#type,
                                    val,
                                    comment: Field::Present(Some(comment)),
                                });
                                continue;
                            }
                            // Skip commenting
                            "n" | "N" | "" => (),
                            _ => {
                                eprintln!("Error: Invalid input");
                                exit(1);
                            }
                        };
                        // Push to the vector of arguments an instance of the ArgsList struct with user-defined values
                        args_list.push(ArgsList {
                            index,
                            op,
                            r#type,
                            val,
                            // No comment was provided, so this field is omitted
                            comment: Field::Missing,
                        });
                    }
                    // Push to the vector of filtered syscalls an instance of the SyscallList
                    // struct with user-defined values
                    filtered_syscall_list.push(SyscallList {
                        syscall: syscall.clone(),
                        args: Field::Present(Some(args_list.clone())),
                    });
                    args_list = Vec::new();
                }
                _ => {
                    eprintln!("\nError: Invalid input");
                    exit(1);
                }
            };
        }
        // Provide a list of possible values for the match_action variable
        let text = 
            "\nEnter the match_action value (can be one of \"allow\", \"errno\", \"kill_thread\", \"kill_process\", \"log\", \"trace\", \"trap\"): ";
        if let Some(stream) = stream { write(stream, text); } else {
                print!("{text}");
                flush();
        };
        input = String::new();
        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            exit(1);
        };
        match_action = input.
            chars().
            filter(|c| !c.is_whitespace()).
            collect();
        match match_action.trim() {
            "allow" | "errno" | "kill_thread" | "kill_process" | "log" | "trace" | "trap" => (),
            _ => {
                eprintln!("\nError: Invalid input");
                exit(1);
            }
        };
        // Provide a list of possible values for the mismatch_action variable
        let text = 
            "\nEnter the mismatch_action value (can be one of \"allow\", \"errno\", \"kill_thread\", \"kill_process\", \"log\", \"trace\", \"trap\"): ";
        if let Some(stream) = stream { write(stream, text); } else {
                print!("{text}");
                flush();
        };
        input = String::new();
        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            exit(1);
        };
        mismatch_action = input.
            chars().
            filter(|c| !c.is_whitespace()).
            collect();
        match mismatch_action.trim() {
            "allow" | "errno" | "kill_thread" | "kill_process" | "log" | "trace" | "trap" => (),
            _ => {
                eprintln!("\nError: Invalid input");
                exit(1);
            }
        };
        // Insert a user-defined key-value pair in the filters hash table
        filters.insert(
            filter_name.clone(),
            FilterList {
                mismatch_action,
                match_action,
                filter: filtered_syscall_list.clone(),
            },
        );
    }

    let filename: String = String::from("filters.json");

    // Create a filters.json file on disk
    let mut writer = if let Ok(file) = File::create(filename) {
        file
    } else {
        eprintln!("\nError: Unable to create file");
        exit(1);
    };

    // Serialize the filters hash table into JSON using serde and write to filters.json
    if write!(
        &mut writer,
        "{}",
        match &serde_json::to_string_pretty(&filters) {
            Ok(json) => json,
            Err(_) => {
                eprintln!("\nError: Unable to serialize to JSON");
                exit(1);
            }
    }
    )
        .is_err()
    {
        eprintln!("\nError: Unable to write to file");
        exit(1);
    };

    // Read the contents of filters.json as this is required by seccompiler
    let json_input = if let Ok(json) = std::fs::read_to_string("filters.json") {
        json
    } else {
        eprintln!("\nError: Unable to read file");
        exit(1);
    };

    println!("\nJSON-formatted seccompiler filter:\n{json_input}");

    // Compile the seccompiler-compatible JSON filter into loadable BPF
    let filter_map: BpfMap = if let Ok(filtermap) = seccompiler::compile_from_json(
        json_input.as_bytes(),
        seccompiler::TargetArch::x86_64,
    ) { filtermap } else {
        eprintln!("\nError: Unable to compile filter into loadable BPF");
        exit(1);
    };

    // Read the BPF program equivalent of the seccomp filter
    let filter = if let Some(filter) = filter_map.get(&filter_name) {
        filter
    } else {
        eprintln!("\nError: Unable to read BPF");
        exit(1);
    };

    println!("\nApplying seccomp-bpf filter...");

    // Install the seccomp filter for the current process
    if seccompiler::apply_filter(filter).is_err() {
        eprintln!("\nError: Unable to install filter");
    };
}

// Pledge/unveil sandboxing
pub fn pledge(application_name: &str, application_args: &Vec<String>, non_interactive_arg: &String, pledge_source: &str, stream: Option<&UnixStream>) {

    let mut promises: Vec<String> = Vec::new();

    // Fetch the pledge binary from the given URL using wget and make it executable using chmod
    // if user has not specified --local flag
    match pledge_source {
        "remote" => {
            println!(
                "\nFetching Justine Tunney's Linux port of OpenBSD's pledge from upstream...\n"
            );
            if Command::new("/bin/bash")
                .arg("-c")
                .arg("wget -q -O ./pledge https://justine.lol/pledge/pledge.com")
                .output()
                .is_err() {
                    eprintln!("\nError: Failed to fetch pledge binary");
                    exit(1);
                };

            println!(
                "\nMaking the pledge binary executable..."
            );

            if Command::new("/bin/bash")
                .arg("-c")
                .arg("chmod +x ./pledge")
                .output()
                .is_err() {
                    eprintln!("\nError: Failed to make the pledge binary executable");
                    exit(1);
                };
        },
        "local" => {
            println!("\nUsing local pledge binary...\n");
        }
        _ => {}
    };

    if !non_interactive_arg.is_empty() {
        let mut command = String::from("./pledge ");
        command.push_str(non_interactive_arg);

        // Checking for possible runtime errors
        let output = if let Ok(output) = Command::new("/bin/bash")
            .arg("-c")
            .arg(&command)
            .output() {
                output
            } else {
                eprintln!("Error: Failed to execute process with sandboxing measures");
                exit(1);
            };

        let stdout = if let Ok(stdout) = String::from_utf8(output.clone().stdout) {
            stdout
        } else {
            eprintln!("Failed to extract stdout");
            exit(1);
        };

        let stderr = if let Ok(stderr) = String::from_utf8(output.stderr) {
            stderr
        } else {
            eprintln!("Failed to extract stderr");
            exit(1);
        };

        if stderr.contains("denied") {
            eprintln!("\nError: Insufficient path permissions. Check unveil privileges.");
            exit(1);
        }

        if stderr.contains("ioctl") ||
            (stderr.as_str() == "" && stdout.as_str() == "") {
            eprintln!("\nError: Insufficient syscall permissions. Check pledge privileges.");
            exit(1);
        }

        println!("\n");

        if Command::new("/bin/bash")
            .arg("-c")
            .arg(&command)
            .spawn()
            .is_err() {
                eprintln!("\nError: Failed to execute process with sandboxing measures");
                exit(1);
        }
        exit(1);
    }

    println!("\n***Pledge sandboxing***\n");

    println!("Here is a list of available pledge promises:");

    // Provide a list of possible promises that can be selected

    println!("stdio: allow stdio, threads, and benign system calls\nrpath: read-only path ops\nwpath: write path ops\ncpath: create path ops\ndpath: create special files\nflock: allow file locking\ntty: terminal ioctls\nrecvfd: allow recvmsg\nsendfd: allow sendmsg\nfattr: allow changing some struct stat bits\ninet: allow IPv4 and IPv6\nunix: allow local sockets\ndns: allow dns\nproc: allow fork process creation and control\nid: allow setuid and friends\nexec: allow executing binaries\nprot_exec: allow creating executable memory (dynamic / ape)\nvminfo: allow executing ape binaries\ntmppath: allow executing ape binaries");

    let text = "\nHow many pledge promises do you want to apply for the process? ";

    if let Some(stream) = stream { write(stream, text); } else {
            print!("{text}");
            flush();
    };
    let mut choice = String::new();
    if let Some(stream) = stream { choice = read(stream); } else if io::stdin().read_line(&mut choice).is_err() {
        eprintln!("\nError: Unable to read input");
        exit(1);
    };

    let choice: u32 = if let Ok(number) = choice.trim().parse() {
        number
    } else {
        eprintln!("\nError: Not a number");
        exit(1);
    };

    for i in 0..choice {
        println!("\nReading promise {}...", i + 1);
        let text = "\nEnter promise: ";
        if let Some(stream) = stream { write(stream, text); } else {
                print!("{text}");
                flush();
        };
        let mut input = String::new();
        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            exit(1);
        };
        let input = input.trim();
        promises.push(input.to_string());
    }

    println!("\n***Unveil sandboxing***\n");
    println!("Here is a list of available unveil path permission values:");
    println!("r: makes PATH available for read-only path operations\nw: makes PATH available for write operations\nx: makes PATH available for execute operations\nc: allows PATH to be created and removed");
    let text = "\nHow many filesystem paths do you want to unveil to the process? ";

    if let Some(stream) = stream { write(stream, text); } else {
            print!("{text}");
            flush();
    };

    let mut number_of_paths: String = String::new();
    let mut paths: Vec<String> = Vec::new();

    if let Some(stream) = stream { number_of_paths = read(stream); } else if io::stdin().read_line(&mut number_of_paths).is_err() {
        eprintln!("\nError: Unable to read input");
        exit(1);
    };

    let number_of_paths: u32 = if let Ok(number) = number_of_paths.trim().parse() {
        number
    } else {
        eprintln!("\nError: Not a number");
        exit(1);
    };

    println!(
        "\nYou can choose to apply unveil PERM defaults (i.e. allow read-only path operations)."
    );
    println!(
        "You can also choose to specify the path operations that you want to allow the process."
    );

    for i in 0..number_of_paths {
        println!("\nFilesystem path {}...\n", i + 1);
        let text = "Do you want to apply unveil PERM defaults? [Y/n] ";
        if let Some(stream) = stream { write(stream, text); } else {
                print!("{text}");
                flush();
        };
        let mut input = String::new();
        if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            exit(1);
        };
        match input.trim() {
            "y" | "Y" | "" => {
                println!("\nApplying unveil PERM defaults...");
                let text = "\nEnter the filesystem path: ";
                if let Some(stream) = stream { write(stream, text); } else {
                        print!("{text}");
                        flush();
                };
                let mut input: String = String::new();
                if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                    eprintln!("\nError: Unable to read input");
                    exit(1);
                };
                let mut path = String::from(" -v ");
                path.push_str(input.trim());
                paths.push(path);
            }
            "n" | "N" => {
                println!("\nProceeding with specific path operations...");
                let text = "\nEnter the filesystem path: ";
                if let Some(stream) = stream { write(stream, text); } else {
                        print!("{text}");
                        flush();
                };
                let mut input: String = String::new();
                if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                    eprintln!("\nError: Unable to read input");
                    exit(1);
                };
                let path = input.trim();
                println!(
                    "Reading path permissions for \"{}\"...",
                    &path
                );
                let text = "\nEnter the filesystem path: ";
                if let Some(stream) = stream { write(stream, text); } else {
                        print!("{text}");
                        flush();
                };
                let mut input: String = String::new();
                if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
                    eprintln!("\nError: Unable to read input");
                    exit(1);
                };
                let perm = &input.trim()[0..];
                let mut unveil_argument = String::from(" -v ");
                unveil_argument.push_str(perm);
                unveil_argument.push(':');
                unveil_argument.push_str(path);
                paths.push(unveil_argument);
            }
            _ => {
                eprintln!("\nError: Invalid input");
                exit(1);
            }
        };
    }

    let mut command = String::from("./pledge");

    for argument in &paths {
        command.push_str(argument);
    }

    command.push_str(" -p \" ");

    for promise in &promises {
        command.push_str(promise);
        command.push(' ');
    }

    command.push_str("\" ");
    command.push(' ');
    command.push_str(application_name);
    command.push(' ');

    for argument in application_args {
        command.push_str(argument);
        command.push(' ');
    }

    println!("\n{}", &command);

    let text = "\nConfirm execution? [Y/n] ";

    if let Some(stream) = stream { write(stream, text); } else {
            print!("{text}");
            flush();
    };
    let mut input = String::new();
    if let Some(stream) = stream { input = read(stream); } else if io::stdin().read_line(&mut input).is_err() {
        eprintln!("\nError: Unable to read input");
        exit(1);
    };

    match input.trim() {
        "y" | "Y" | "" => {
            println!("\nRunning process with pledge sandboxing...\n");
            // Execute the process with pledge+unveil sandboxing
            // Seccomp filter has been previously installed
            // and will get applied to the process,
            // producing a core dump if some essential syscall was disallowed
            if Command::new("/bin/bash")
                .arg("-c")
                    .arg(command)
                    .spawn()
                    .is_err()
            {
                println!("Failed to execute process with sandboxing measures");
            };
        }
        _ => {
            println!("\nExiting...");
        }
    };
}

#[must_use] pub fn get_syscall_list(
    application_name: &String,
    application_args: &Vec<String>
) -> Vec<LurkList> {
    let mut syscall_list: Vec<LurkList> = Vec::new();
    let filename: String = String::from("output.json");
    // Create an output.json file on disk for saving lurk's JSON output
    let mut writer = if let Ok(writer) = File::create(filename) {
        writer
    } else {
        eprintln!("\nError: Unable to create file");
        return Vec::new();
    };
    let output = if let Ok(output) = Command::new("lurk")
        .arg("-j")
        .arg(application_name)
        .args(application_args)
        .output() { output } else {
            eprintln!("\nError: Command failed to execute");
            return Vec::new();
        };

    // Write the JSON output to output.json
    if writer
        .write_all(String::from_utf8_lossy(&output.stdout).as_bytes())
            .is_err()
    {
        eprintln!("\nError: Unable to write to file");
        return Vec::new();
    };

    let json = if let Ok(json) = File::open("output.json") {
        json
    } else {
        eprintln!("\nError: Unable to parse JSON");
        return Vec::new();
    };

    // Deserialize the JSON into a struct for accessing the individual fields
    let syscalls = serde_json::Deserializer::from_reader(json).into_iter::<LurkList>();

    for syscall in syscalls {
        let syscall = if let Ok (syscall) = syscall {
            syscall
        } else {
            eprintln!("\nError: Failed to deserialize JSON");
            return Vec::new();
        };
        // Extract syscall name and args and save as an instance of the LurkList struct
        syscall_list.push(LurkList {
            syscall: syscall.syscall,
            args: syscall.args,
        });
    }
    syscall_list
}

pub fn flush() {
    // Flush output
    if io::stdout().flush().is_err() {
        println!("Flush failed");
    };
}

pub fn check_args() {
    if let Some(argument) = env::args().nth(1) {
        match argument.as_str() {
            "--check" => {
                check_deps();
            },
            "--no-check" => {
                println!("\nSkipping dependency checking...");
            },
            _ => {
                eprintln!("Error: Dependency checking argument not provided");
                exit(1);
            }
        };
    } else {
        eprintln!("Error: Insufficient number of arguments supplied");
        exit(1);
    }
}

#[must_use] pub fn check_pledge() -> String {
    if let Some(argument) = env::args().nth(2) {
        match argument.as_str() {
            "--local" => {
                return String::from("local");
            },
            "--remote" => {
                return String::from("remote");
            },
            _ => {
                eprintln!("Error: Pledge binary source argument not provided");
                exit(1);
            }
        };
    };
    String::from("error")
}

pub fn check_deps() {
    println!("This code has wget and lurk as its dependencies. Checking to ensure the binaries are installed before proceeding...");

    // Check if /bin/wget exists
    if metadata("/bin/wget").is_err() {
        eprintln!("\nError: wget not found. Please install using your system's package manager.");
        exit(1);
    };

    // Retrieve path to user's home directory
    let output = if let Ok(home_dir) = Command::new("/bin/bash")
        .arg("-c")
        .arg("echo $HOME")
        .output() { home_dir } else {
            eprintln!("\nError: Failed to retrieve path to home directory");
            exit(1);
        };

    // Convert the Vec<u8> output to str
    let target_dir = if let Ok(home_dir) = str::from_utf8(&output.stdout) {
        home_dir
    } else {
        eprintln!("\nError: Got non UTF-8 data");
        exit(1);
    };

    let mut target_dir = target_dir.trim().to_string();

    // Append the remaining portion of the conventional path to the lurk binary
    target_dir.push_str("/.cargo/bin/lurk");

    // Check if $HOME/.cargo/bin/lurk or /bin/lurk exists
    if std::fs::metadata(target_dir).is_err() {
        eprintln!("\nError: cargo-installed lurk-cli binary not found. Checking to see if it has been installed using the system's package manager...");
        if std::fs::metadata("/bin/lurk").is_err() {
            eprintln!("\nError: lurk not found. Please install using cargo (\"cargo install lurk-cli\") or your system's package manager.");
            exit(1);
        };
    };

    println!("\nChecking if the BPF Just in Time (JIT) compiler is enabled...");

    // Retrieve the value of /proc/sys/net/core/bpf_jit_enable
    let output = if let Ok(value) =  Command::new("/bin/bash")
        .arg("-c")
        .arg("cat /proc/sys/net/core/bpf_jit_enable")
        .output() { value } else {
            eprintln!("\nError: Failed to check if BPF JIT compiler is enabled");
            exit(1);
        };

    let bpf_jit_val = if let Ok(home_dir) = str::from_utf8(&output.stdout) {
        home_dir
    } else {
        eprintln!("\nError: Got non UTF-8 data");
        exit(1);
    };

    // If the value is not equal to 1, that implies the BPF JIT compiler is disabled
    if bpf_jit_val.trim() != "1" {
        eprintln!("\nThe BPF JIT compiler is disabled. It is recommended to enable it to minimize syscall overhead.");
        exit(1);
    };

}

fn read(stream: &UnixStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    let response = response.trim().to_string();
    response

}


fn write(stream: &UnixStream, text: &str) {
    let mut unix_stream = if let Ok(stream) = stream.try_clone() {
            stream
        } else {
            eprintln!("Cannot copy stream");
            exit(1);
    };
    if unix_stream.write(text.as_bytes()).is_err() {
        eprintln!("\nUnable to write to stream");
        exit(1);
    }
}

#[must_use] pub fn check_api() -> bool {
    if let Some(argument) = env::args().nth(3) { match argument.as_str() {
        "--api" => {
            println!("\nEntering API mode...");
            return true;
        },
        "--no-api" => {
            println!("\nEntering interactive mode...");
            return false;
        },
        _ => {
            eprintln!("\nError: API flag incorrect or not provided");
            exit(1);
        }
    }};
    false
}


pub fn main() {
    let mut application_name: String = String::new();
    let mut application_args: Vec<String> = Vec::new();
    let mut non_interactive_arg: String = String::new();
    let pledge_source: String = check_pledge();
    let socket_path = "/tmp/seccomp-pledge.sock";
    let listener;


    // Check if the user intends to run the program in non-interactive mode
    if let Some(argument) = env::args().nth(4) { match argument.as_str() {
        "-v" | "-p" => {
            println!("Entering non-interactive mode...");
            println!("\nSkipping seccomp-bpf filtering...");
            let mut promises_index = 0;
            // Quotes are stripped off while passing arguments
            // This workaround prefixes each promise
            // with the promise flag instead
            // and adds spaces wherever necessary
            for (index, argument) in env::args().enumerate() {
                if index < 4 { continue; }
                non_interactive_arg.push_str(argument.clone().as_str());
                if index == promises_index {
                    non_interactive_arg.push_str("\" ");
                    continue;
                }
                non_interactive_arg.push(' ');
                if &argument == "-p" {
                    promises_index = index + 1;
                    non_interactive_arg.push('\"');
                }
            }
            pledge("", &Vec::new(), &non_interactive_arg, &pledge_source, None);
            exit(1);
        },
            _ => {
                // Retrieve the arguments passed to the process, if any
                for (index, argument) in env::args().enumerate() {
                    if index < 4 { continue; }
                    if index == 4 {
                        application_name = argument.clone();
                        continue;
                    };
                    application_args.push(argument.clone());
                }
            }
    }};

    // Run in interactive mode
    check_args();

    if check_api() {
        if std::fs::metadata(socket_path).is_ok() {
            println!("\nA socket is already present at {}. Deleting...", &socket_path);
            if std::fs::remove_file(socket_path).is_err() {
                eprintln!("\nError: Unable to remove previous socket at {:?}", &socket_path);
                exit(1);
            };
        }
        println!("\nCreating new socket...");
        listener = UnixListener::bind(socket_path).expect("Unable to create socket");
        if OS == "linux" {
            println!("\nYou are running a Linux system. Seccomp-bpf is supported. Proceeding with seccomp filtering...");
            if let Ok((socket, _addr)) = listener.accept() {
                seccomp(&application_name, &application_args, Some(&socket));
                pledge(&application_name, &application_args, &String::new(), &pledge_source, Some(&socket));
            };
        };

    } else {}
}
