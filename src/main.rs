use context::generate_context_aware_prompt;
use nix::sys::signal::{kill, Signal};
use nix::unistd::{dup2, execvp, fork, ForkResult};
use nix::{libc, pty::*};
use regex::Regex;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use termion::event::Key;
use termion::input::TermRead;
use termion::{self, raw::IntoRawMode};

mod context;

#[derive(Debug, Deserialize)]
struct Flag {
    name: String,
    placeholder: String,
    optional: bool,
    default: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CommandSchema {
    bin: String,
    subcommand: Option<String>,
    action: Option<String>,
    flags: Vec<Flag>,
}

fn main() {
    // Set up the PTY
    let result = openpty(None, None).expect("Failed to open PTY");
    let slave_fd = result.slave;
    let master_fd = result.master;

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child process: Replace stdin, stdout, stderr with the slave PTY
            dup2(slave_fd.as_raw_fd(), 0).expect("Failed to dup2 stdin");
            dup2(slave_fd.as_raw_fd(), 1).expect("Failed to dup2 stdout");
            dup2(slave_fd.as_raw_fd(), 2).expect("Failed to dup2 stderr");
            drop(master_fd); // Close the master and slave file descriptors
            drop(slave_fd);

            // Start Zsh
            let zsh = CString::new("zsh").unwrap();
            execvp(&zsh, &[&zsh]).expect("Failed to exec zsh");
        }
        Ok(ForkResult::Parent { child }) => {
            // Parent process: Interact with the PTY
            drop(slave_fd); // Close the slave fd in the parent

            // Set terminal to raw mode
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut stdout_lock = stdout.lock().into_raw_mode().unwrap();
            let mut stdin_lock = stdin.lock();

            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();

            let master_fd_raw = master_fd.as_raw_fd();

            // Thread to read from PTY and write to stdout
            let reader_thread = thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                while r.load(Ordering::SeqCst) {
                    let n = unsafe {
                        libc::read(master_fd_raw, buffer.as_mut_ptr() as *mut _, buffer.len())
                    };
                    if n > 0 {
                        let written = unsafe {
                            libc::write(
                                libc::STDOUT_FILENO,
                                buffer.as_ptr() as *const _,
                                n as usize,
                            )
                        };
                        if written < 0 {
                            eprintln!("Failed to write to stdout");
                            break;
                        }
                    } else {
                        break;
                    }
                }
            });

            loop {
                let mut buffer = [0u8; 1];
                let n = stdin_lock.read(&mut buffer);
                match n {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }
                        let b = buffer[0];
                        match b {
                            0x10 => {
                                // Ctrl+P
                                drop(stdin_lock); // Drop stdin lock for prompt
                                prompt_for_command(&mut stdout_lock, master_fd_raw);
                                stdin_lock = stdin.lock(); // Reacquire stdin lock
                            }
                            0x03 => {
                                // Ctrl+C
                                running.store(false, Ordering::SeqCst);
                                kill(child, Signal::SIGKILL).unwrap();
                                break;
                            }
                            _ => {
                                // Write byte to PTY master fd
                                unsafe {
                                    libc::write(
                                        master_fd_raw,
                                        &b as *const u8 as *const libc::c_void,
                                        1,
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading byte: {}", e);
                        break;
                    }
                }
            }

            reader_thread.join().unwrap();
            drop(stdout_lock);
        }
        Err(_) => {
            eprintln!("Fork failed");
        }
    }
}

fn validate_command_schema(schema: &CommandSchema) -> Result<(), String> {
    if schema.bin.is_empty() {
        return Err("The `bin` field is required.".to_string());
    }
    for flag in &schema.flags {
        if flag.name.is_empty() {
            return Err("Each flag must have a `name`.".to_string());
        }
        if !flag.optional && flag.default.is_none() && flag.placeholder.is_empty() {
            return Err(format!(
                "Flag '{}' is required but does not have a placeholder or default value.",
                flag.name
            ));
        }
    }
    Ok(())
}

fn parse_command(
    schema: CommandSchema,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    // Validate schema
    validate_command_schema(&schema)?;

    // Build the command
    let mut command = schema.bin.clone();
    if let Some(subcommand) = schema.subcommand {
        command.push(' ');
        command.push_str(&subcommand);
    }
    if let Some(action) = schema.action {
        command.push(' ');
        command.push_str(&action);
    }

    // Add flags
    for flag in schema.flags {
        if let Some(user_value) = user_inputs.get(&flag.placeholder) {
            // Add the flag and user-provided value
            command.push(' ');
            command.push_str(&flag.name);
            command.push(' ');
            command.push_str(user_value);
        } else if !flag.optional {
            // Add default value if available
            if let Some(default_value) = flag.default {
                command.push(' ');
                command.push_str(&flag.name);
                command.push(' ');
                command.push_str(&default_value);
            } else {
                return Err(format!("Missing required parameter: {}", flag.placeholder));
            }
        }
    }

    Ok(command.trim().to_string())
}

fn read_user_input<W: Write>(stdin: &io::Stdin, stdout: &mut W) -> String {
    let mut input = String::new();
    let stdin_lock = stdin.lock();

    for c in stdin_lock.keys() {
        match c.unwrap() {
            Key::Char('\n') | Key::Char('\r') => break,
            Key::Char('\x7f') | Key::Backspace => {
                if !input.is_empty() {
                    input.pop();
                    write!(stdout, "\x08 \x08").unwrap();
                    stdout.flush().unwrap();
                }
            }
            Key::Char(ch) => {
                input.push(ch);
                write!(stdout, "{}", ch).unwrap();
                stdout.flush().unwrap();
            }
            Key::Ctrl('c') => {
                input.clear();
                break;
            }
            _ => {}
        }
    }

    input
}

fn display_command_preview<W: Write>(stdout: &mut W, schema: &CommandSchema, rows: u16) {
    let preview = format!(
        "{} {} {}",
        schema.bin,
        schema.subcommand.clone().unwrap_or_default(),
        schema.action.clone().unwrap_or_default()
    );

    write!(
        stdout,
        "{}Command: {}\n",
        termion::cursor::Goto(1, rows - 3),
        preview
    )
    .unwrap();
    stdout.flush().unwrap();
}

fn gather_user_inputs<W: Write>(
    stdout: &mut W,
    stdin: io::Stdin,
    schema: &CommandSchema,
    rows: u16,
) -> HashMap<String, String> {
    let mut user_inputs = HashMap::new();

    for flag in &schema.flags {
        let prompt_message = if flag.optional {
            format!("{} (optional): ", flag.placeholder)
        } else {
            format!("{} (required): ", flag.placeholder)
        };

        write!(
            stdout,
            "{}{}{}",
            termion::cursor::Goto(1, rows - 2),
            termion::clear::CurrentLine,
            prompt_message
        )
        .unwrap();
        stdout.flush().unwrap();

        let input = read_user_input(&stdin, stdout);

        // If the input is empty and the parameter is optional, skip it
        if input.trim().is_empty() && flag.optional {
            continue;
        }

        // If the input is non-empty or required, add it to the user inputs
        if !input.trim().is_empty() || !flag.optional {
            user_inputs.insert(flag.placeholder.clone(), input.trim().to_string());
        }
    }

    user_inputs
}

fn construct_command(schema: CommandSchema, user_inputs: &HashMap<String, String>) -> String {
    let mut command = schema.bin.clone();
    if let Some(subcommand) = schema.subcommand {
        command.push(' ');
        command.push_str(&subcommand);
    }
    if let Some(action) = schema.action {
        command.push(' ');
        command.push_str(&action);
    }

    for flag in schema.flags {
        if let Some(value) = user_inputs.get(&flag.placeholder) {
            // If user provided a value, include the flag and value
            command.push(' ');
            command.push_str(&flag.name);
            command.push(' ');
            command.push_str(value);
        } else if !flag.optional {
            // If required but not provided, use the default value
            if let Some(default) = flag.default {
                command.push(' ');
                command.push_str(&flag.name);
                command.push(' ');
                command.push_str(&default);
            }
        }
        // Skip the flag entirely if it's optional and no input was provided
    }

    command
}

fn send_to_shell(master_fd_raw: RawFd, command: &str) {
    let bracketed_paste_start = b"\x1b[200~";
    let bracketed_paste_end = b"\x1b[201~";
    let command_bytes = command.as_bytes();
    let mut full_command = Vec::new();
    full_command.extend_from_slice(bracketed_paste_start);
    full_command.extend_from_slice(command_bytes);
    full_command.extend_from_slice(bracketed_paste_end);

    unsafe {
        libc::write(
            master_fd_raw,
            full_command.as_ptr() as *const libc::c_void,
            full_command.len(),
        );
    }
}

fn prompt_for_command<W: Write>(stdout: &mut W, master_fd_raw: RawFd) {
    let (_cols, rows) = termion::terminal_size().unwrap_or((80, 24));
    let stdin = io::stdin();

    // Save cursor position to restore later
    write!(stdout, "{}", termion::cursor::Save).unwrap();
    stdout.flush().unwrap();

    // Prompt for user input
    write!(stdout, "{}", termion::cursor::Goto(1, rows - 1)).unwrap();
    write!(stdout, ":").unwrap();
    stdout.flush().unwrap();

    let input = read_user_input(&stdin, stdout);

    // Clear the input prompt
    write!(
        stdout,
        "{}{}",
        termion::clear::CurrentLine,
        termion::cursor::Restore
    )
    .unwrap();
    stdout.flush().unwrap();

    if input.trim().is_empty() {
        return; // No input provided
    }

    // Get the raw command (JSON format) from ChatGPT
    let schema = get_command_from_chatgpt(&input);

    // Gather user input for placeholders
    let user_inputs = gather_user_inputs(stdout, stdin, &schema, rows);

    // Construct the final shell command
    let final_command = construct_command(schema, &user_inputs);

    // Restore cursor position before placing the command
    write!(stdout, "{}", termion::cursor::Restore).unwrap();
    stdout.flush().unwrap();

    // Send the completed command to the shell via PTY
    send_to_shell(master_fd_raw, &final_command);
}

fn get_command_from_chatgpt(prompt: &str) -> CommandSchema {
    let api_key = env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY not set");

    let client = reqwest::blocking::Client::new();

    let message = generate_context_aware_prompt();

    let request_body = json!({
        "model": "gpt-4-turbo",
        "messages": [
            {
                "role": "system",
                "content": message
            },
            {
                "role": "user",
                "content": format!(
                    "Generate the shell command to {}. Always respond strictly in JSON format, adhering to the schema provided.",
                    prompt
                )
            }
        ],
        "temperature": 0,
    });

    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&request_body)
        .send();

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let response_json: serde_json::Value = response.json().unwrap_or_else(|e| {
                    eprintln!("Failed to parse response JSON: {}", e);
                    std::process::exit(1);
                });

                // Extract the JSON content from the GPT response
                let command_json = response_json["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or_else(|| {
                        eprintln!("Unexpected response format");
                        std::process::exit(1);
                    });

                // Deserialize the JSON response into CommandSchema
                serde_json::from_str(command_json).unwrap_or_else(|e| {
                    eprintln!("Failed to deserialize command JSON: {}", e);
                    std::process::exit(1);
                })
            } else {
                eprintln!("API Error: {:?}", response.text());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Request error: {}", e);
            std::process::exit(1);
        }
    }
}
