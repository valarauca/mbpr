//! Nom based decoder for Memcached Binary Packet Protol
//!
//! Supports all current opcodes. The goal of this interface is
//! simplicity and speed. There is very little validation done on
//! packet construction the expectation of that is placed on higher
//! libraries.
//!
//! The parsing is fairly strict.
//!
//! For examples please see [tests](github.com/valarauca/mbpr) directory
//! or keep reading.
//!
//! This was created based on [Memcached Wiki](https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped)
//!

#[macro_use]
extern crate nom;
use nom::{IResult,ErrorKind};
use std::intrinsics::copy_nonoverlapping;
use std::mem::transmute;

/// Binary Packet Protocols
mod opcode;
pub use opcode::OpCode;

/// Status Codes for Response Packets
mod status;
pub use status::StatusField;

/// RequestHeaders/Packets
mod request;
pub use request::{Request,OwnedRequest,ReqHeader};

/// ResponseHeaders/Packets
mod response;
pub use response::{Response,OwnedResponse,ResHeader};

macro_rules! write_data {
  ($val: expr, $len: expr, $start: expr, $buf: expr) => {
    unsafe {
      let swap = $val.to_be();
      let buff: [u8;$len] = transmute(swap);
      copy_nonoverlapping(buff.as_ptr(), $buf.get_unchecked_mut($start as usize), $len);
      $start += $len;
    }
  }
}


/// Parsing Error structure
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum Fault {
  /// Opcode does not conform to the standard
  BadOpCode,
  /// Status code does not conform to standard
  BadStatus,
  /// More data is needed to fully parse packet. 
  Incomplete,
  /// Fixed initial field
  ///
  ///* Request = `0x80`
  ///* Response = `0x81`
  ///* DataType = `0x00`
  ///
  /// Was wrong.
  BadMagic,
  InvalidPacket
}
/// Internal Result type
pub enum ParseResult<T> {
  Ok(T),
  Err(Fault)
}
impl<T> ParseResult<T> {
  /// Unwraps the value. Panics on failure
  #[inline(always)]
  pub fn unwrap(self) -> T {
    match self {
      ParseResult::Ok(x) => x,
      ParseResult::Err(e) => panic!("ParseResult::unwrap called on Err {:?}", e)
    }
  }
  /// Checks if value is okay
  #[inline(always)]
  pub fn is_ok(&self) -> bool {
    match self {
       &ParseResult::Ok(_) => true,
       _ => false
    }
  }
  /// Check if the value is error
  #[inline(always)]
  pub fn is_err(&self) -> bool {
    ! self.is_ok()
  }
  /// Get Okay Value
  #[inline(always)]
  pub fn ok(self) -> Option<T> {
    match self {
      ParseResult::Ok(x) => Some(x),
      ParseResult::Err(_) => None
    }
  }
  /// Get Error Value
  #[inline(always)]
  pub fn err(self) -> Option<Fault> {
    match self {
      ParseResult::Ok(_) => None,
      ParseResult::Err(e) => Some(e)
    }
  }
}
impl<'a,T> From<IResult<&'a [u8],T>> for ParseResult<T> {

  /// You can ignore this
  ///
  /// It is an internal method for handling nom's parser errors
  #[inline(always)]
  fn from(x: IResult<&'a [u8], T>) -> ParseResult<T> {
    match x {
      IResult::Done(_,x) => ParseResult::Ok(x),
      IResult::Incomplete(_) => ParseResult::Err(Fault::Incomplete),
      IResult::Error(ErrorKind::Custom(0x83u32)) => ParseResult::Err(Fault::BadStatus),
      IResult::Error(ErrorKind::Custom(0x81u32)) => ParseResult::Err(Fault::BadOpCode),
      IResult::Error(ErrorKind::Tag) => ParseResult::Err(Fault::BadMagic),
      IResult::Error(_) => ParseResult::Err(Fault::InvalidPacket)
    }
  }
}

/// Data type used to encode data efficient
///
/// This structure has been built from the ground up to avoid 
/// branching while encoding. 
pub struct Encoder {
  data: Vec<u8>,
  pos: isize
}
impl Encoder {
  /// Pass an already constructed packet in. This will allocate a buffer
  /// the size of that packet
  #[inline(always)]
  pub fn new<P: PacketVal>(msg: &P) -> Encoder {
    let len = msg.total_len();
    let mut v = Vec::with_capacity(len);
    unsafe{ v.set_len(len) };
    Encoder {
      data: v,
      pos: 0
    }
  }
  /// To avoid allocations this method allows for a pre-allocated vector
  /// be passed in. The Vector's size will be checked, and it **MAY** be resized
  /// if too small. If it's capacity is sufficient no allocations will be done.
  #[inline(always)]
  pub fn from_vec<P: PacketVal>(msg: &P, x: Vec<u8>) -> Encoder {
    let mut x = x;
    let len = msg.total_len();
    let capac = x.capacity();
    /* resize if needed */
    if capac < len {
      let delta = capac - len;
      x.reserve(delta);
    }
    unsafe{ x.set_len(len) };
    Encoder {
      data: x,
      pos: 0
    }
  }
  /// Consumes this type (destroying it) but returns the underlying vector
  /// as to not dellocator it's memory (be used again).
  #[inline(always)]
  pub fn get_vec(self) -> Vec<u8> {
    self.data
  }
  /// Used internally for testing, maybe useful to the developer reading this
  /// this allows for the input value to set the len/capacity of the internal
  /// memory
  ///
  /// #Unsafe
  ///
  /// This method is unsafe. If you encode a packet LARGER then the method
  /// your program may seg fault as there is no bounds checking when encoding.
  #[inline(always)]
  pub unsafe fn with_capacity(size: usize) -> Self {
    let mut v = Vec::<u8>::with_capacity(size);
    v.set_len(size);
    Encoder {
      data: v,
      pos: 0
    }
  }
  /// While the underlying `vec` is fully populated this returns
  /// only the data written to it. So if `with::capacity` is used
  /// to create a buffer _larger_ then a packet this can be used
  /// to read only the packet data.
  #[inline(always)]
  pub fn as_slice<'a>(&'a self) -> &'a [u8] {
    use std::slice;

    unsafe{ 
      slice::from_raw_parts(self.data.as_ptr() as *mut u8, self.len())
    }
  }
  /// Get length of data written to the encoder
  #[inline(always)]
  pub fn len(&self) -> usize {
      self.pos as usize
  }
  /// Encode a u8 used internally.
  #[inline(always)]
  pub fn encode_u8(&mut self, x: u8) {
    let i = self.len();
    self.data[i] = x;
    self.pos += 1;
  }
  /// Encode a u16 used internally.
  #[inline(always)]
  pub fn encode_u16(&mut self, x: u16) {
    write_data!(x, 2, self.pos, self.data.as_mut_slice());
  }
  /// Encode a u32 used internally.
  #[inline(always)]
  pub fn encode_u32(&mut self, x: u32) {
    write_data!(x, 4, self.pos, self.data.as_mut_slice());
  }
  /// Encode a u64 used internally.
  #[inline(always)]
  pub fn encode_u64(&mut self, x: u64) {
    write_data!(x, 8, self.pos, self.data.as_mut_slice());
  }
  /// Encode a [u8] used internally.
  #[inline(always)]
  pub fn encode_slice(&mut self, x: &[u8]) {
    let len = x.len();
    let s = self.len();
    unsafe {
      copy_nonoverlapping(x.as_ptr(), self.data.get_unchecked_mut(s), len);
    }
    self.pos += len as isize;
  }
}

/// Trait for encoding the value into a packet
pub trait Encoding {

  /// Simple method to write the internal data into a buffer
  fn encode(&self, buffer: &mut Encoder);
}
impl Encoding for u8 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    buffer.encode_u8(self.clone());
  }
}
impl Encoding for [u8] {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    buffer.encode_slice(self);
  }
}
impl<'a> Encoding for Option<&'a [u8]> {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    match self {
      &Option::None => { },
      &Option::Some(ref x) => {
        buffer.encode_slice(x);
      }
    };
  }
}
impl Encoding for u16 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    buffer.encode_u16(self.clone());
  }
}
impl Encoding for u32 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    buffer.encode_u32(self.clone());
  }
}
impl Encoding for u64 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    buffer.encode_u64(self.clone());
  }
}
impl Encoding for Vec<u8> {
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    buffer.encode_slice(self.as_slice());
  }
}

/// Values encoded within Memcached packets
///
/// These are basic getter methods that _all_
/// valid memcached BPR packets will contain.
///
/// This is a seperate trait because other
/// traits inheriate it.
pub trait PacketVal {
  fn get_keylen(&self) -> usize;
  fn get_extralen(&self) -> usize;
  fn get_bodylen(&self) -> usize;
  /// The total length of the packet
  #[inline(always)]
  fn total_len(&self) -> usize {
    self.get_keylen()
      +
    self.get_extralen()
      +
    self.get_bodylen()
      +
    24
  }
}


#[test]
fn test_encode_u8() {
  let mut e = unsafe{ Encoder::with_capacity(100) };
  assert_eq!(e.len(), 0);
  assert_eq!(e.as_slice(), b"");
  (0xFFu8).encode(&mut e);
  assert_eq!(e.len(), 1);
  assert_eq!(e.as_slice(), b"\xFF");
}

#[test]
fn test_encode_u16() {
  let mut e = unsafe{ Encoder::with_capacity(100) };
  assert_eq!(e.len(), 0);
  assert_eq!(e.as_slice(), b"");
  (0xAAFFu16).encode(&mut e);
  assert_eq!(e.len(), 2);
  assert_eq!(e.as_slice(), b"\xAA\xFF");
}

#[test]
fn test_encode_u32() {
  let mut e = unsafe{ Encoder::with_capacity(100) };
  assert_eq!(e.len(), 0);
  assert_eq!(e.as_slice(), b"");
  (0x44BBAAFFu32).encode(&mut e);
  assert_eq!(e.len(), 4);
  assert_eq!(e.as_slice(), b"\x44\xBB\xAA\xFF");
}

#[test]
fn test_encode_u64() {
  let mut e = unsafe{ Encoder::with_capacity(100) };
  assert_eq!(e.len(), 0);
  assert_eq!(e.as_slice(), b"");
  (0x1166884444BBAAFFu64).encode(&mut e);
  assert_eq!(e.len(), 8);
  assert_eq!(e.as_slice(), b"\x11\x66\x88\x44\x44\xBB\xAA\xFF");
}


#[test]
fn test_encode_slice() {
  let mut e = unsafe{ Encoder::with_capacity(100) };
  assert_eq!(e.len(), 0);
  assert_eq!(e.as_slice(), b"");
  let slice: &'static [u8] = b"Hello World Test";
  slice.encode(&mut e);
  assert_eq!(e.len(), slice.len());
  assert_eq!(e.as_slice(), b"Hello World Test");
}


#[test]
fn test_encoding_vec() {
  let mut e = unsafe{ Encoder::with_capacity(100) };
  assert_eq!(e.len(), 0);
  assert_eq!(e.as_slice(), b"");
  let slice: Vec<u8> = vec![1,2,3,4,5,6,7,8,9,10];
  slice.encode(&mut e);
  assert_eq!(e.len(), slice.len());
  assert_eq!(e.as_slice(), b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A");
}
