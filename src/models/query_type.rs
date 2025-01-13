#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QueryType {
    A,
    NS,
    CNAME,
    MX,
    AAAA,
    UNKNOWN(u16),
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::UNKNOWN(qtype) => qtype,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}
