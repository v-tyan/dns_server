use crate::types::Result;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    pub fn get(&mut self, pos: usize) -> Result<u8> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        Ok(self.buf[pos])
    }

    pub fn set_u8(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set_u8(pos, (val >> 8) as u8)?;
        self.set_u8(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        Ok(&self.buf[start..start + len])
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        let res = ((self.read_u8()? as u16) << 8) | (self.read_u8()? as u16);

        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        let res = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | (self.read_u8()? as u32);

        Ok(res)
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u8((val >> 24) as u8)?;
        self.write_u8((val >> 16) as u8)?;
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn read_name(&mut self) -> Result<String> {
        let mut domain = String::new();
        let mut pos = self.pos();
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            // Handle jump scenario (2 MSBs of len is set)
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }

            pos += 1;

            if len == 0 {
                break;
            }

            domain.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            domain.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(domain)
    }

    pub fn write_qname(&mut self, qname: &String) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if (len > 63) {
                return Err("Label max length of 63 exeeded".into());
            }

            self.write_u8(len as u8)?;
            for byte in label.bytes() {
                self.write_u8(byte)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}
