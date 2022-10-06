use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolType(pub u8);
/// Unspecified symbol type
pub const STT_NOTYPE: SymbolType = SymbolType(0);
/// Data object symbol
pub const STT_OBJECT: SymbolType = SymbolType(1);
/// Code object symbol
pub const STT_FUNC: SymbolType = SymbolType(2);
/// Section symbol
pub const STT_SECTION: SymbolType = SymbolType(3);
/// File name symbol
pub const STT_FILE: SymbolType = SymbolType(4);
/// Common data object symbol
pub const STT_COMMON: SymbolType = SymbolType(5);
/// Thread-local data object symbol
pub const STT_TLS: SymbolType = SymbolType(6);
/// Indirect code object symbol
pub const STT_GNU_IFUNC: SymbolType = SymbolType(10);

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            STT_NOTYPE => "unspecified",
            STT_OBJECT => "data object",
            STT_FUNC => "code object",
            STT_SECTION => "section",
            STT_FILE => "file name",
            STT_COMMON => "common data object",
            STT_TLS => "thread-local data object",
            STT_GNU_IFUNC => "indirect code object",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolBind(pub u8);
/// Local symbol
pub const STB_LOCAL: SymbolBind = SymbolBind(0);
/// Global symbol
pub const STB_GLOBAL: SymbolBind = SymbolBind(1);
/// Weak symbol
pub const STB_WEAK: SymbolBind = SymbolBind(2);
/// Unique symbol
pub const STB_GNU_UNIQUE: SymbolBind = SymbolBind(10);

impl fmt::Display for SymbolBind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            STB_LOCAL => "local",
            STB_GLOBAL => "global",
            STB_WEAK => "weak",
            STB_GNU_UNIQUE => "unique",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolVis(pub u8);
/// Default symbol visibility
pub const STV_DEFAULT: SymbolVis = SymbolVis(0);
/// Processor-specific hidden visibility
pub const STV_INTERNAL: SymbolVis = SymbolVis(1);
/// Hidden visibility
pub const STV_HIDDEN: SymbolVis = SymbolVis(2);
/// Protected visibility
pub const STV_PROTECTED: SymbolVis = SymbolVis(3);

impl fmt::Display for SymbolVis {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            STV_DEFAULT => "default",
            STV_INTERNAL => "internal",
            STV_HIDDEN => "hidden",
            STV_PROTECTED => "protected",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol value
    pub value: u64,
    /// Symbol size
    pub size: u64,
    /// Section index
    pub shndx: u16,
    /// Symbol type
    pub symtype: SymbolType,
    /// Symbol binding
    pub bind: SymbolBind,
    /// Symbol visibility
    pub vis: SymbolVis,
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Symbol: Value: {:#010x} Size: {:#06x} Type: {} Bind: {} Vis: {} Section: {} Name: {}",
            self.value, self.size, self.symtype, self.bind, self.vis, self.shndx, self.name
        )
    }
}
