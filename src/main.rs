use optional_field::{serde_optional_fields, Field};
use seccompiler::BpfMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::metadata;
use std::fs::File;
use std::io;
use std::io::Write;
use std::process::Command;
use std::str;

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
pub fn seccomp(application_name: &String, application_args: &Vec<String>) {
    let mut filters: HashMap<String, FilterList> = HashMap::new();
    let mut filter_name: String = String::new();
    let mut match_action: String;
    let mut mismatch_action: String;
    let mut args_list: Vec<ArgsList> = Vec::new();
    let mut number_of_filters: String = String::new();

    // Filtering begins
    println!("\n***Seccomp-BPF Filtering***\n");

    print!("How many filters do you want to construct for the process? ");

    flush();

    if io::stdin().read_line(&mut number_of_filters).is_err() {
        eprintln!("\nError: Failed to read input");
        return;
    };

    let number_of_filters: u32 = if let Ok(number) = number_of_filters.trim().parse() {
        number
    } else {
        eprintln!("\nError: Not a number");
        return;
    };

    print!("\nHere is a list of syscalls (with name and arguments) spawned by the process:\n");

    flush();

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
        print!("\nEnter a name for this filter: ");
        flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            return;
        };
        filter_name = input.chars().filter(|c| !c.is_whitespace()).collect();
        print!("\nArguments distinguish between syscalls of the same name. How many syscalls will be passed to the seccomp filter? ");
        flush();
        input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            return;
        };
        let count = if let Ok(number) = input.trim().parse() {
            number
        } else {
            eprintln!("\nError: Not a number");
            return;
        };
        println!("\nYou can choose to construct a universal rule for the syscall that will be applied regardless of arguments.");
        println!("You can also choose to pattern-match specific arguments of the syscall.");
        for _ in 0..count {
            let mut input: String = String::new();
            // Provide a choice for specifying a syscall without arguments or pattern-matching
            // arguments of some syscall
            print!("\nDo you want to create a universal rule for the syscall? [y/N] ");
            flush();
            if io::stdin().read_line(&mut input).is_err() {
                eprintln!("\nError: Unable to read input");
                return;
            };
            match input.trim() {
                // Universal rule for some syscall
                "y" | "Y" => {
                    let mut input = String::new();
                    println!("\nConstructing a universal rule...");
                    print!("\nEnter the name of the syscall: ");
                    flush();
                    if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("\nError: Unable to read input");
                        return;
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
                    print!("\nEnter the name of the syscall: ");
                    flush();
                    if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("\nError: Unable to read input");
                        return;
                    };
                    let syscall: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                    input = String::new();
                    print!("\nHow many arguments do you want to pattern-match? ");
                    flush();
                    if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("\nError: Unable to read input");
                        return;
                    };
                    let number_of_args = if let Ok(number) = input.trim().parse() {
                        number
                    } else {
                        eprintln!("\nError: Not a number");
                        return;
                    };
                    for j in 0..number_of_args {
                        let mut input = String::new();
                        println!("\nPattern-matching argument {}...", j + 1);
                        print!("\nEnter the index of the argument as per the syscall definition: ");
                        flush();
                        if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            return;
                        };
                        let index = if let Ok(number) = input.trim().parse() {
                            number
                        } else {
                            eprintln!("\nError: Not a number");
                            return;
                        };
                        input = String::new();
                        // Provide a list of possible values for the comparison operator
                        print!("\nEnter the comparison operator (\"eq\" for \"equal to\", \"ne\" for \"not equal to\", \"lt\" for \"less than\", \"le\" for \"less than or equal to\", \"gt\" for \"greater than\", \"ge\" for \"greater than or equal to\", \"masked_eq\" for masked equality): ");
                        flush();
                        if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            return;
                        };
                        let op: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                        input = String::new();
                        // Provide a list of possible values for the argument size
                        print!("\nEnter the argument size (dword = 4 bytes, qword = 8 bytes): ");
                        flush();
                        if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            return;
                        };
                        let r#type: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                        input = String::new();
                        print!("\nEnter the value to be checked against: ");
                        flush();
                        if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            return;
                        };
                        let val = if let Ok(number) = input.trim().parse() {
                            number
                        } else {
                            eprintln!("\nError: Not a number");
                            return;
                        };
                        input = String::new();
                        // Providing comments is made optional by seccompiler since it is primarily
                        // for reference
                        print!("\nDo you wish to provide an optional comment to provide meaning to each numeric value? [y/N] ");
                        flush();
                        if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("\nError: Unable to read input");
                            return;
                        };
                        match input.trim() {
                            // Provide comments for syscall args
                            "y" | "Y" => {
                                let mut input: String = String::new();
                                print!("\nEnter the comment: ");
                                flush();
                                if io::stdin().read_line(&mut input).is_err() {
                                    eprintln!("\nError: Unable to read input");
                                    return;
                                };
                                let comment =
                                    input.chars().filter(|c| !c.is_whitespace()).collect();
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
                                return;
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
                    return;
                }
            };
        }
        // Provide a list of possible values for the match_action variable
        print!("\nEnter the match_action value (can be one of \"allow\", \"errno\", \"kill_thread\", \"kill_process\", \"log\", \"trace\", \"trap\"): ");
        flush();
        input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            return;
        };
        match_action = input.chars().filter(|c| !c.is_whitespace()).collect();
        match match_action.trim() {
            "allow" | "errno" | "kill_thread" | "kill_process" | "log" | "trace" | "trap" => (),
            _ => {
                eprintln!("\nError: Invalid input");
                return;
            }
        };
        // Provide a list of possible values for the mismatch_action variable
        print!("\nEnter the mismatch_action value (can be one of \"allow\", \"errno\", \"kill_thread\", \"kill_process\", \"log\", \"trace\", \"trap\"): ");
        flush();
        input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            return;
        };
        mismatch_action = input.chars().filter(|c| !c.is_whitespace()).collect();
        match mismatch_action.trim() {
            "allow" | "errno" | "kill_thread" | "kill_process" | "log" | "trace" | "trap" => (),
            _ => {
                eprintln!("\nError: Invalid input");
                return;
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
        return;
    };

    // Serialize the filters hash table into JSON using serde and write to filters.json
    if write!(
        &mut writer,
        "{}",
        match &serde_json::to_string_pretty(&filters) {
            Ok(json) => json,
            Err(_) => {
                eprintln!("\nError: Unable to serialize to JSON");
                return;
            }
    }
    )
        .is_err()
    {
        eprintln!("\nError: Unable to write to file");
        return;
    };

    // Read the contents of filters.json as this is required by seccompiler
    let json_input = if let Ok(json) = std::fs::read_to_string("filters.json") {
        json
    } else {
        eprintln!("\nError: Unable to read file");
        return;
    };

    println!("\nJSON-formatted seccompiler filter:\n{json_input}");

    // Compile the seccompiler-compatible JSON filter into loadable BPF
    let filter_map: BpfMap = if let Ok(filtermap) = seccompiler::compile_from_json(
        json_input.as_bytes(),
        seccompiler::TargetArch::x86_64,
    ) { filtermap } else {
        eprintln!("\nError: Unable to compile filter into loadable BPF");
        return;
    };

    // Read the BPF program equivalent of the seccomp filter
    let filter = if let Some(filter) = filter_map.get(&filter_name) {
        filter
    } else {
        eprintln!("\nError: Unable to read BPF");
        return;
    };

    println!("\nApplying seccomp-bpf filter...");

    // Install the seccomp filter for the current process
    if seccompiler::apply_filter(filter).is_err() {
        eprintln!("\nError: Unable to install filter");
    };
}

// Pledge/unveil sandboxing
pub fn pledge(application_name: &str, application_args: &Vec<String>, non_interactive_arg: &String) {

    let mut promises: Vec<String> = Vec::new();

    // Fetch the pledge binary from the given URL using wget and make it executable using chmod
    // if pledge binary is not already present in current path
    if metadata("./pledge").is_err() {
        println!(
            "\nFetching Justine Tunney's Linux port of OpenBSD's pledge...\n"
        );
        if Command::new("/bin/bash")
            .arg("-c")
            .arg("wget -q -O ./pledge https://justine.lol/pledge/pledge.com")
            .output()
            .is_err() {
                eprintln!("\nError: Failed to fetch pledge binary");
                return;
            };

        println!(
            "\nMaking the pledge binary executable...\n"
        );

        if Command::new("/bin/bash")
            .arg("-c")
            .arg("chmod +x ./pledge")
            .output()
            .is_err() {
                eprintln!("\nError: Failed to make the pledge binary executable");
                return;
            };
    } else {
        println!("\nPledge binary found at current path...\n");
    }

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
                return;
            };

        let stdout = if let Ok(stdout) = String::from_utf8(output.clone().stdout) {
            stdout
        } else {
            eprintln!("Failed to extract stdout");
            return;
        };

        let stderr = if let Ok(stderr) = String::from_utf8(output.stderr) {
            stderr
        } else {
            eprintln!("Failed to extract stderr");
            return;
        };

        if stderr.contains("denied") {
            eprintln!("\nError: Insufficient path permissions. Check unveil privileges.");
            return;
        }

        if stderr.contains("ioctl") ||
            (stderr.as_str() == "" && stdout.as_str() == "") {
            eprintln!("\nError: Insufficient syscall permissions. Check pledge privileges.");
            return;
        }

        if Command::new("/bin/bash")
            .arg("-c")
            .arg(&command)
            .spawn()
            .is_err() {
                eprintln!("\nError: Failed to execute process with sandboxing measures");
                return;
        }
        return;
    }

    println!("\n***Pledge sandboxing***\n");

    println!("Here is a list of available pledge promises:");

    // Provide a list of possible promises that can be selected

    println!("stdio: allow stdio, threads, and benign system calls\nrpath: read-only path ops\nwpath: write path ops\ncpath: create path ops\ndpath: create special files\nflock: allow file locking\ntty: terminal ioctls\nrecvfd: allow recvmsg\nsendfd: allow sendmsg\nfattr: allow changing some struct stat bits\ninet: allow IPv4 and IPv6\nunix: allow local sockets\ndns: allow dns\nproc: allow fork process creation and control\nid: allow setuid and friends\nexec: allow executing binaries\nprot_exec: allow creating executable memory (dynamic / ape)\nvminfo: allow executing ape binaries\ntmppath: allow executing ape binaries");

    print!("\nHow many pledge promises do you want to apply for the process? ");

    flush();

    let mut choice = String::new();

    if io::stdin().read_line(&mut choice).is_err() {
        eprintln!("\nError: Failed to read input");
        return;
    };

    let choice: u32 = if let Ok(number) = choice.trim().parse() {
        number
    } else {
        eprintln!("\nError: Not a number");
        return;
    };

    for i in 0..choice {
        let mut input = String::new();
        print!("\nEnter promise {}: ", i + 1);
        flush();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Failed to read input");
            return;
        };
        let input = input.trim();
        promises.push(input.to_string());
    }

    println!("\n***Unveil sandboxing***\n");
    println!("Here is a list of available unveil path permission values:");
    println!("r: makes PATH available for read-only path operations\nw: makes PATH available for write operations\nx: makes PATH available for execute operations\nc: allows PATH to be created and removed");
    print!("\nHow many filesystem paths do you want to unveil to the process? ");

    flush();

    let mut number_of_paths: String = String::new();
    let mut paths: Vec<String> = Vec::new();

    if io::stdin().read_line(&mut number_of_paths).is_err() {
        eprintln!("\nError: Unable to read input");
        return;
    };
    let number_of_paths: u32 = if let Ok(number) = number_of_paths.trim().parse() {
        number
    } else {
        eprintln!("\nError: Not a number");
        return;
    };

    println!(
        "\nYou can choose to apply unveil PERM defaults (i.e. allow read-only path operations)."
    );
    println!(
        "You can also choose to specify the path operations that you want to allow the process."
    );

    for i in 0..number_of_paths {
        println!("\nFilesystem path {}...\n", i + 1);
        print!("Do you want to apply unveil PERM defaults? [Y/n] ");
        flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            return;
        };
        match input.trim() {
            "y" | "Y" | "" => {
                println!("\nApplying unveil PERM defaults...");
                print!("\nEnter the filesystem path: ");
                flush();
                let mut input: String = String::new();
                if io::stdin().read_line(&mut input).is_err() {
                    eprintln!("\nError: Unable to read input");
                    return;
                };
                let mut path = String::from(" -v ");
                path.push_str(input.trim());
                paths.push(path);
            }
            "n" | "N" => {
                println!("\nProceeding with specific path operations...");
                print!("\nEnter the filesystem path: ");
                flush();
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_err() {
                    eprintln!("\nError: Unable to read input");
                    return;
                };
                let path = input.trim();
                print!(
                    "Enter the path permissions for \"{}\" that the process will have: ",
                    &path
                );
                flush();
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_err() {
                    eprintln!("\nError: Unable to read input");
                    return;
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
                return;
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

    print!("\nIs this the final command you wish to execute? [Y/n] ");

    flush();

    let mut input = String::new();

    if io::stdin().read_line(&mut input).is_err() {
        eprintln!("\nError: Failed to read input");
        return;
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
            println!("\nAborting...");
        }
    };
}

#[must_use] pub fn get_syscall_list(
    application_name: &String,
    application_args: &Vec<String>,
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

pub fn check_arg() {
    if let Some(argument) = env::args().nth(1) {
        match argument.as_str() {
            "--check" | "-check" => {
                check();
            },
            "--no_check" | "-no_check" | "-no-check" | "--no-check" => {
                println!("\nSkipping dependency checking...");
            },
            _ => {
                eprintln!("Error: Dependency checking argument not provided");
            }
        };
    } else {
        eprintln!("Error: Insufficient number of arguments supplied");
    }
}

pub fn check() {
    println!("This code has wget and lurk as its dependencies. Checking to ensure the binaries are installed before proceeding...");

    // Check if /bin/wget exists
    if std::fs::metadata("/bin/wget").is_err() {
        eprintln!("\nError: wget not found. Please install using your system's package manager.");
        return;
    };

    // Retrieve path to user's home directory
    let output = if let Ok(home_dir) = Command::new("/bin/bash")
        .arg("-c")
        .arg("echo $HOME")
        .output() { home_dir } else {
            eprintln!("\nError: Failed to retrieve path to home directory");
            return;
        };

    // Convert the Vec<u8> output to str
    let target_dir = if let Ok(home_dir) = str::from_utf8(&output.stdout) {
        home_dir
    } else {
        eprintln!("\nError: Got non UTF-8 data");
        return;
    };

    let mut target_dir = target_dir.trim().to_string();

    // Append the remaining portion of the conventional path to the lurk binary
    target_dir.push_str("/.cargo/bin/lurk");

    // Check if $HOME/.cargo/bin/lurk or /bin/lurk exists
    if std::fs::metadata(target_dir).is_err() {
        eprintln!("\nError: cargo-installed lurk-cli binary not found. Checking to see if it has been installed using the system's package manager...");
        if std::fs::metadata("/bin/lurk").is_err() {
            eprintln!("\nError: lurk not found. Please install using cargo (\"cargo install lurk-cli\") or your system's package manager.");
            return;
        };
    };

    println!("\nChecking if the BPF Just in Time (JIT) compiler is enabled...");

    // Retrieve the value of /proc/sys/net/core/bpf_jit_enable
    let output = if let Ok(value) =  Command::new("/bin/bash")
        .arg("-c")
        .arg("cat /proc/sys/net/core/bpf_jit_enable")
        .output() { value } else {
            eprintln!("\nError: Failed to check if BPF JIT compiler is enabled");
            return;
        };

    let bpf_jit_val = if let Ok(home_dir) = str::from_utf8(&output.stdout) {
        home_dir
    } else {
        eprintln!("\nError: Got non UTF-8 data");
        return;
    };

    // If the value is not equal to 1, that implies the BPF JIT compiler is disabled
    if bpf_jit_val.trim() != "1" {
        eprintln!("\nThe BPF JIT compiler is disabled. It is recommended to enable it to minimize syscall overhead.");
    };

}

pub fn main() {
    let mut application_name: String = String::new();
    let mut application_args: Vec<String> = Vec::new();
    let mut non_interactive_arg: String = String::new();

    // Check if the user intends to run the program in non-interactive mode
    if let Some(argument) = env::args().nth(2) { match argument.as_str() {
        "-v" | "-p" => {
            println!("Entering non-interactive mode...");
            println!("\nSkipping seccomp-bpf filtering...");
            check_arg();
            let mut promises_index = 0;
            // Quotes are stripped off while passing arguments
            // This workaround prefixes each promise
            // with the promise flag instead
            // and adds spaces wherever necessary
            for (index, argument) in env::args().enumerate() {
                if index < 2 { continue; }
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
            pledge("", &Vec::new(), &non_interactive_arg);
            return;
        },
            _ => {
                // Retrieve the arguments passed to the process, if any
                for (index, argument) in env::args().enumerate() {
                    if index < 2 { continue; }
                    if index == 2 {
                        application_name = argument.clone();
                        continue;
                    };
                    application_args.push(argument.clone());
                }
            }
    }};

    // Run in interactive mode
    check_arg();

    // Pattern-matching the OS type
    if OS == "linux" {
        print!("\nYou are running a Linux system. Seccomp-bpf is supported. Do you want to proceed with seccomp filtering? [Y/n] ");
        let mut input = String::new();
        flush();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("\nError: Unable to read input");
            return;
        };
        match input.trim() {
            "y" | "Y" | "" => {
                println!("\nProceeding with seccomp filtering...");
                seccomp(&application_name, &application_args);
                pledge(&application_name, &application_args, &String::new());
            }
            "n" | "N" => {
                println!("\nProceeding without seccomp filtering...");
                pledge(&application_name, &application_args, &String::new());
            }
            _ => {
                eprintln!("\nError: Invalid input");
            }
        };
    } else {
        println!("\nYou are running a non-Linux system. Seccomp-bpf is unsupported. Proceeding without seccomp filtering...");
        println!("Application name: {}, application args:{:?}", &application_name, &application_args);
        pledge(&application_name, &application_args, &String::new());
    }

}
