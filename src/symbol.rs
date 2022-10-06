use crate::gabi;

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

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Symbol: Value: {:#010x} Size: {:#06x} Type: {} Bind: {} Vis: {} Section: {} Name: {}",
            self.value, self.size, self.symtype, self.bind, self.vis, self.shndx, self.name
        )
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolType(pub u8);

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::STT_NOTYPE => "unspecified",
            gabi::STT_OBJECT => "data object",
            gabi::STT_FUNC => "code object",
            gabi::STT_SECTION => "section",
            gabi::STT_FILE => "file name",
            gabi::STT_COMMON => "common data object",
            gabi::STT_TLS => "thread-local data object",
            gabi::STT_GNU_IFUNC => "indirect code object",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolBind(pub u8);

impl std::fmt::Display for SymbolBind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::STB_LOCAL => "local",
            gabi::STB_GLOBAL => "global",
            gabi::STB_WEAK => "weak",
            gabi::STB_GNU_UNIQUE => "unique",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolVis(pub u8);

impl std::fmt::Display for SymbolVis {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::STV_DEFAULT => "default",
            gabi::STV_INTERNAL => "internal",
            gabi::STV_HIDDEN => "hidden",
            gabi::STV_PROTECTED => "protected",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}
