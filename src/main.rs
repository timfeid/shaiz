use nix::sys::signal::{kill, Signal};
use nix::unistd::{dup2, execvp, fork, ForkResult};
use nix::{libc, pty::*};
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
            // Close the master and slave file descriptors
            drop(master_fd); // OwnedFd will close the fd when dropped
            drop(slave_fd); // OwnedFd will close the fd when dropped

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

            // For handling Ctrl+C
            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();

            // Get the RawFd from master_fd
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

            // Main loop: Read input and write to PTY
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
                                // Drop stdin_lock to release the lock on stdin
                                drop(stdin_lock);

                                // Enter prompt mode
                                prompt_for_command(&mut stdout_lock, master_fd_raw);

                                // Re-initialize stdin_lock after prompt
                                stdin_lock = stdin.lock();
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

            // Wait for the reader thread to finish
            reader_thread.join().unwrap();

            // Restore the terminal settings before exiting
            drop(stdout_lock);
        }
        Err(_) => {
            eprintln!("Fork failed");
        }
    }
}

fn prompt_for_command<W: Write>(stdout: &mut W, master_fd_raw: RawFd) {
    // Get terminal size
    let (_cols, rows) = termion::terminal_size().unwrap_or((80, 24));

    // Save cursor position
    write!(stdout, "{}", termion::cursor::Save).unwrap();
    stdout.flush().unwrap();

    // Move cursor to bottom line
    write!(stdout, "{}", termion::cursor::Goto(1, rows)).unwrap();
    write!(stdout, ":").unwrap();
    stdout.flush().unwrap();

    // Read input in raw mode
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
                        // Move cursor back, overwrite the character with space, move back again
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
                    // Cancel the prompt
                    input.clear();
                    break;
                }
                _ => {}
            }
        }
    } // stdin_lock is dropped here

    // Clear the prompt line
    write!(
        stdout,
        "{}{}",
        termion::clear::CurrentLine,
        termion::cursor::Restore
    )
    .unwrap();
    stdout.flush().unwrap();

    // If input is empty or cancelled, do nothing
    if input.is_empty() {
        return;
    }

    // Call OpenAI API to get the command
    let command = get_command_from_chatgpt(&input);

    // Send the command to the shell via the PTY master file descriptor using bracketed paste
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

fn get_command_from_chatgpt(prompt: &str) -> String {
    let api_key = env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY not set");

    let client = reqwest::blocking::Client::new();

    let request_body = json!({
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "You are an assistant that outputs only shell commands."},
            {"role": "user", "content": format!("Generate the shell command to {}. Only output the command without any explanation.", prompt)}
        ],
        "max_tokens": 100,
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
