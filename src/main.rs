use nix::sys::signal::{kill, Signal};
use nix::unistd::{dup2, execvp, fork, ForkResult};
use nix::{libc, pty::*};
use regex::Regex;
use serde_json::json;
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

fn prompt_for_command<W: Write>(stdout: &mut W, master_fd_raw: RawFd) {
    let (_cols, rows) = termion::terminal_size().unwrap_or((80, 24));

    write!(stdout, "{}", termion::cursor::Save).unwrap();
    stdout.flush().unwrap();

    write!(stdout, "{}", termion::cursor::Goto(1, rows - 1)).unwrap();
    write!(stdout, ":").unwrap();
    stdout.flush().unwrap();

    let stdin = io::stdin();
    let mut input = String::new();

    {
        let stdin_lock = stdin.lock();
        for c in stdin_lock.keys() {
            match c.unwrap() {
                Key::Char('\n') | Key::Char('\r') => {
                    break;
                }
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
    }

    write!(
        stdout,
        "{}{}",
        termion::clear::CurrentLine,
        termion::cursor::Restore
    )
    .unwrap();
    stdout.flush().unwrap();

    if input.is_empty() {
        return;
    }

    let raw_command = get_command_from_chatgpt(&input);

    // Clean the GPT command
    let command_with_placeholders = clean_gpt_command(&raw_command);

    // Display the cleaned command with placeholders above the prompts
    write!(
        stdout,
        "{}Command: {}\n",
        termion::cursor::Goto(1, rows - 3),
        command_with_placeholders
    )
    .unwrap();
    stdout.flush().unwrap();

    // Find placeholders using regex
    let placeholder_regex = Regex::new(r"<(\w+)(?::([^>]+))?>").unwrap();

    let mut filled_command = command_with_placeholders.clone();

    for cap in placeholder_regex.captures_iter(&command_with_placeholders) {
        let param_name = &cap[1];
        let default_value = cap.get(2).map_or("", |m| m.as_str());

        // Prompt user to fill in the parameter
        if default_value.is_empty() {
            // Mandatory input since no default is provided
            write!(
                stdout,
                "{}{}{} (required): ",
                termion::cursor::Goto(1, rows - 2),
                termion::clear::CurrentLine,
                param_name
            )
            .unwrap();
        } else {
            // Optional input with default
            write!(
                stdout,
                "{}{}{} (default: {}): ",
                termion::cursor::Goto(1, rows - 2),
                termion::clear::CurrentLine,
                param_name,
                default_value
            )
            .unwrap();
        }
        stdout.flush().unwrap();

        let mut user_input = String::new();
        let stdin_lock = stdin.lock();
        for c in stdin_lock.keys() {
            match c.unwrap() {
                Key::Char('\n') | Key::Char('\r') => {
                    break;
                }
                Key::Char('\x7f') | Key::Backspace => {
                    if !user_input.is_empty() {
                        user_input.pop();
                        write!(stdout, "\x08 \x08").unwrap();
                        stdout.flush().unwrap();
                    }
                }
                Key::Char(ch) => {
                    user_input.push(ch);
                    write!(stdout, "{}", ch).unwrap();
                    stdout.flush().unwrap();
                }
                Key::Ctrl('c') => {
                    user_input.clear();
                    break;
                }
                _ => {}
            }
        }

        let final_value = if user_input.trim().is_empty() {
            if default_value.is_empty() {
                eprintln!("{} is required. Aborting.", param_name);
                return;
            } else {
                default_value.to_string()
            }
        } else {
            user_input.trim().to_string()
        };

        // Replace placeholder in command
        filled_command = filled_command.replace(&cap[0], &final_value);
    }

    // Clear the parameter prompt line
    write!(
        stdout,
        "{}{}",
        termion::clear::CurrentLine,
        termion::cursor::Restore
    )
    .unwrap();
    stdout.flush().unwrap();

    // Send the completed command to the shell via PTY
    let bracketed_paste_start = b"\x1b[200~";
    let bracketed_paste_end = b"\x1b[201~";
    let command_bytes = filled_command.as_bytes();
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

fn clean_gpt_command(command: &str) -> String {
    let trimmed = command.trim();

    // Check if the command starts and ends with backticks
    if trimmed.starts_with("```") && trimmed.ends_with("```") {
        // Remove the first and last lines
        let lines: Vec<&str> = trimmed.lines().collect();
        if lines.len() > 2 {
            // Join all lines except the first and last
            return lines[1..lines.len() - 1].join("\n").trim().to_string();
        }
    }

    // Return the command as-is if no markdown wrapper is found
    trimmed.to_string()
}

fn get_command_from_chatgpt(prompt: &str) -> String {
    let api_key = env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY not set");

    let client = reqwest::blocking::Client::new();

    let request_body = json!({
        "model": "gpt-4-turbo",
        "messages": [
            {
                "role": "system",
                "content": "You are an assistant that outputs only shell commands for macOS with Homebrew and Zsh. Use the following format for parameters in commands: \
                - For mandatory parameters: <param_name> (e.g., <source>). \
                - For mandatory parameters with a default value: <param_name:default_value> (e.g., <destination:/default/path>). \
                "
            },
            {
                "role": "user",
                "content": format!(
                    "Generate the shell command to {}. Use <param_name>, <param_name:default_value> where appropriate. Only output the shell command without any explanation, markdown, or extra text.",
                    prompt
                )
            }
        ],
        "max_tokens": 100,
        "temperature": 0,
    });

    // set git's default merge setting to rebase
    // zip contents of a folder

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
                let command = response_json["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or_else(|| {
                        eprintln!("Unexpected response format");
                        std::process::exit(1);
                    })
                    .trim();
                command.to_string()
            } else {
                eprintln!("API Error: {:?}", response.text());
                "echo Error getting command from ChatGPT".to_string()
            }
        }
        Err(e) => {
            eprintln!("Request error: {}", e);
            "echo Error getting command from ChatGPT".to_string()
        }
    }
}
