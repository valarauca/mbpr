//! Nom based decoder for Memcached Binary Packet Protol
//!
//! This supports the protocol as of what is in the standard
//! for 1.5 (the 1.6 extensions which are not formally
//! specified are not supported).


#[macro_use]
extern crate nom;
pub use nom::{IResult,Needed,ErrorKind};
use std::mem::transmute;

/// Binary Packet Protocols
pub mod opcode;

/// Status Codes for Response Packets
pub mod status;

/// RequestHeaders/Packets
pub mod request;

/// ResponseHeaders/Packets
pub mod response;

/// Trait for handling packets which can hold status
pub trait ResponseStatus {

  /// check's status field.
  ///
  /// If the `StatusField::NoError` this returns
  /// `Result::Ok(())` to allow for error checking
  /// to be a bit more ideomatic
  fn status(&self) -> Result<(), status::StatusField>;
}

/// Trait for encoding the value into a packet
pub trait Encoding {

  /// Simple method to write the internal
  /// data into a buffer
  fn encode(&self, buffer: &mut Vec<u8>);
}
impl Encoding for u8 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    buffer.push(self.clone());
  }
}
impl Encoding for [u8] {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    buffer.extend_from_slice(self);
  }
}
impl<'a> Encoding for Option<&'a [u8]> {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    match self {
      &Option::None => { },
      &Option::Some(ref x) => {
        x.encode(buffer);
      }
    };
  }
}
impl Encoding for u16 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    let swap: u16 = self.to_be();
    let arr: [u8;2] = unsafe{ transmute(swap)};
    arr.encode(buffer);
  }
}
impl Encoding for u32 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    let swap: u32 = self.to_be();
    let arr: [u8;4] = unsafe{ transmute(swap)};
    arr.encode(buffer);
  }
}
impl Encoding for u64 {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    let swap: u64 = self.to_be();
    let arr: [u8;8] = unsafe{ transmute(swap)};
    arr.encode(buffer);
  }
}

/// Every valid packet has an OpCode
///
/// This is lifted into a trait so
/// I don't have to reimplemnt for
/// every type
pub trait Op {
  fn get_opcode(&self) -> opcode::OpCode;
}

/// Values encoded within Memcached packets
///
/// These are basic getter methods that _all_
/// valid memcached BPR packets will contain.
///
/// This is a seperate trait because other
/// traits inheriate it.
pub trait PacketVal: Op {
  fn get_keylen(&self) -> usize;
  fn get_extralen(&self) -> usize;
  fn get_bodylen(&self) -> usize;
  fn get_opaque(&self) -> usize;
  fn get_cas(&self) -> usize;
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


/// Trait for all memcached packets
pub trait Packet<'a>: PacketVal{
  fn has_extra(&self) -> bool;
  fn has_key(&self) -> bool;
  fn has_body(&self) -> bool;
  fn get_extra(&'a self) -> Option<&'a [u8]>;
  fn get_key(&'a self) -> Option<&'a [u8]>;
  fn get_body(&'a self) -> Option<&'a [u8]>;
}
