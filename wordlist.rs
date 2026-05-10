// ============================================================
// wordlist.rs — Wordlist reading and candidate streaming
//
// This module handles reading wordlist files efficiently and
// feeding candidates to the cracker.
//
// Design decisions:
//
// 1. Line-by-line buffered reading
//    We do NOT load the entire wordlist into memory. rockyou.txt
//    is 134MB. Argon2 cracking already uses significant RAM per
//    thread. We read one line at a time using BufReader.
//
// 2. Channel-based streaming
//    We use a crossbeam channel to stream lines from a reader
//    thread into the rayon thread pool. This decouples I/O from
//    computation — the reader runs ahead and buffers lines while
//    the cracker threads are busy hashing.
//
// 3. Fast line counting
//    We do a separate pass to count lines before cracking starts.
//    This lets us show an accurate progress bar. We count bytes
//    looking for '\n' rather than parsing lines — much faster.
// ============================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use crossbeam_channel::{bounded, Receiver, Sender};


// ============================================================
// count_lines
//
// Counts the number of lines in a file by counting '\n' bytes.
// Much faster than reading line-by-line through the string layer.
//
// We read in 64KB chunks — this matches typical OS page sizes
// and keeps the read calls efficient.
//
// Returns the line count, or 0 if the file can't be read.
// ============================================================
pub fn count_lines(path: &Path) -> std::io::Result<u64> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut count: u64 = 0;
    let mut buf = [0u8; 64 * 1024];  // 64KB read buffer

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;  // EOF
        }
        // Count newlines in this chunk — each one is a line ending
        count += buf[..bytes_read].iter().filter(|&&b| b == b'\n').count() as u64;
    }

    // Handle files that don't end with a newline — add 1 for the
    // last line if the file is non-empty
    if count == 0 {
        // Check if file has any content at all
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 0 {
            count = 1;
        }
    }

    Ok(count)
}


// ============================================================
// stream_wordlist
//
// Opens a wordlist file and streams its lines through a channel.
//
// Returns a Receiver<String> — the cracker reads from this.
// The sender runs in a background thread so I/O doesn't block
// the rayon thread pool.
//
// Channel capacity: 10,000 lines buffered.
// This is enough to keep the cracker threads fed without using
// too much memory for the buffer itself.
//
// The sender thread exits when it reaches EOF or encounters an
// error. The channel closing signals the receiver that iteration
// is complete — no explicit "done" message needed.
// ============================================================
pub fn stream_wordlist(path: &Path) -> std::io::Result<Receiver<String>> {
    let path = path.to_path_buf();  // Clone so we can move into the thread

    // `bounded(10_000)` creates a channel that blocks the sender
    // when 10,000 items are queued — this provides natural backpressure.
    // If the cracker is slower than the reader (always true for Argon2),
    // the reader will wait rather than consuming unbounded memory.
    let (tx, rx): (Sender<String>, Receiver<String>) = bounded(10_000);

    // Spawn a dedicated reader thread — this is a real OS thread
    // (not a tokio task) because file I/O blocks and we don't want
    // to occupy a rayon worker thread with blocking reads.
    std::thread::spawn(move || {
        let file = match File::open(&path) {
            Ok(f)  => f,
            Err(_) => return,  // Can't open file — close the channel
        };

        // BufReader wraps the file with a read buffer.
        // Without it, each `lines()` call would make a separate
        // syscall for each character — very slow.
        let reader = BufReader::with_capacity(64 * 1024, file);

        for line in reader.lines() {
            match line {
                Ok(l) => {
                    // `send()` blocks when the channel is full (backpressure).
                    // If the receiver is gone (cracker found the password),
                    // send() returns Err and we stop reading.
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,  // Read error — stop
            }
        }
        // When this thread exits, `tx` is dropped, which closes
        // the channel. The receiver will see this as exhaustion.
    });

    Ok(rx)
}


// ============================================================
// Unit tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper: write a temp file with given content, return its path
    fn make_temp_wordlist(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_count_lines_empty_file() {
        let f = make_temp_wordlist("");
        assert_eq!(count_lines(f.path()).unwrap(), 0);
    }

    #[test]
    fn test_count_lines_single_word() {
        let f = make_temp_wordlist("wolf\n");
        assert_eq!(count_lines(f.path()).unwrap(), 1);
    }

    #[test]
    fn test_count_lines_multiple_words() {
        let f = make_temp_wordlist("wolf\nfenrir\nciaaran\n");
        assert_eq!(count_lines(f.path()).unwrap(), 3);
    }

    #[test]
    fn test_stream_delivers_all_lines() {
        let f = make_temp_wordlist("wolf\nfenrir\nsniffsnorf\n");
        let rx = stream_wordlist(f.path()).unwrap();

        let lines: Vec<String> = rx.iter().collect();
        assert_eq!(lines, vec!["wolf", "fenrir", "sniffsnorf"]);
    }
}
