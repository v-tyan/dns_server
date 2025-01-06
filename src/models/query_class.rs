#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QueryClass {
    IN,
    CH,
    HS,
    ANY,
    UNKNOWN(u16),
}

impl QueryClass {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryClass::IN => 1,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
            QueryClass::ANY => 255,
            QueryClass::UNKNOWN(qclass) => qclass,
        }
    }

    pub fn from_num(num: u16) -> QueryClass {
        match num {
            1 => QueryClass::IN,
            3 => QueryClass::CH,
            4 => QueryClass::HS,
            255 => QueryClass::ANY,
            _ => QueryClass::UNKNOWN(num),
        }
    }
}
