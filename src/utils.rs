use std;
pub fn get_string(data: &[u8], start: usize) -> Result<String, std::string::FromUtf8Error> {
    let mut end: usize = 0;
    for i in start..data.len() {
        if data[i] == 0u8 {
            end = i;
            break;
        }
    }
    let mut rtn = String::with_capacity(end - start);
    for i in start..end {
        rtn.push(data[i] as char);
    }
    Ok(rtn)
}
