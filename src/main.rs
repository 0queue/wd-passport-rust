#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::env;
use std::io::Write;

use termion::input::TermRead;

mod passport;

/*
 * From https://github.com/0-duke/wdpassport-utils
 * also ended up learning a bunch from https://github.com/KenMacD/wdpassport-utils
 */


fn read_password() -> std::io::Result<String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(b"Drive password: ").unwrap();
    stdout.flush().unwrap();

    let pass = stdin.read_passwd(&mut stdout)?;

    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();
    Ok(pass.unwrap())
}

fn main() -> Result<(), Box<std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let passport = passport::Passport::new(args.get(1).unwrap())?;

    let (security, cipher, key_reset_enabler) = passport.status()?;

    println!(
        "SecurityStatus: {:?}, CipherId: {:?}, Key Reset Enabler: {:?}",
        security, cipher, key_reset_enabler
    );

    if passport.unlock(&read_password().unwrap()) {
        println!("Success!");
    } else {
        println!("Password incorrect");
    }

    let (security, cipher, key_reset_enabler) = passport.status()?;

    println!(
        "SecurityStatus: {:?}, CipherId: {:?}, Key Reset Enabler: {:?}",
        security, cipher, key_reset_enabler
    );

    Ok(())
}
