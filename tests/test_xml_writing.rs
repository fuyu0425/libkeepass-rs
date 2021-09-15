mod tests {
    use keepass::*;
    use std::io::Write;
    use std::{fs::File, path::Path};

    #[test]
    fn dump_kdbx3() -> Result<()> {
        // not implemented yet
        //let path = Path::new("tests/resources/test_db_with_password.kdbx");
        //let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;
        //let res = db.dump(Some("demopass"), None)?;
        //println!("{}", String::from_utf8(res).unwrap());
        Ok(())
    }
    #[test]
    fn dump_kdbx4() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let new_path = Path::new("kdbx4-dump.bin");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;
        let res = db.dump(Some("demopass"), None)?;
        let mut f = std::fs::File::create(new_path)?;
        f.write_all(&res)?;
        f.flush()?;

        let db_parsed = Database::open(&mut File::open(new_path)?, Some("demopass"), None)?;
        assert_eq!(db_parsed, db);
        Ok(())
    }
}
