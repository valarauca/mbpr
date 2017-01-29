
//everything in a nom macro is dead code q.q
#![allow(dead_code)]
use super::{
  ParseResult,
  Encoder,
  Encoding,
  PacketVal,
};
use super::opcode::{
  OpCode,
  opcode_parse
};
use super::nom::{
  be_u8,
  be_u16,
  be_u32,
  be_u64
};
use super::status::{
  StatusField,
  status_parse
};

/*
 *Request Header Section
 */

/// Memcached Response Packet Header
///
/// This is the first 24 bytes of the packet
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ResHeader {
  code: OpCode,
  extralen: u8,
  status: StatusField,
  keylen: u16,
  bodylen: u32,
  opaque: u32,
  cas: u64
}
impl ResHeader {
  #[inline(always)]
  pub fn get_opcode(&self) -> OpCode {
    self.code.clone()
  }
  #[inline(always)]
  pub fn get_opaque(&self) -> u32 {
    self.opaque
  } 
  #[inline(always)]
  pub fn get_cas(&self) -> u64 {
      self.cas
  }
  /// Check Status Field
  ///
  /// If the condition `StatusField::NoError` is set this
  /// will return `Ok(())`, if there is an error it will
  /// return it in `Err(StatusField::_)`
  ///
  /// All _standard_ error codes are implemented.
  #[inline(always)]
  pub fn check_status(&self) -> Result<(),StatusField> {
    self.status.check_status()
  }
  /// Parse a packet header
  #[inline(always)]
  pub fn parse(x: &[u8]) -> ParseResult<ResHeader> {
    ParseResult::from(parse_res_header(x))
  }
}
impl PacketVal for ResHeader {
  #[inline(always)]
  fn get_keylen(&self) -> usize {
    self.keylen as usize
  }
  #[inline(always)]
  fn get_extralen(&self) -> usize {
    self.extralen as usize
  }
  #[inline(always)]
  fn get_bodylen(&self) -> usize {
    self.bodylen as usize
  }
}
impl Encoding for ResHeader {
  
  /// Relatively fast method for encoding header
  ///
  /// If you avoid the `with::capacity` method for
  /// constructing `Encoder` this method is prefectly
  /// safe and will encode the packet header without
  /// any bounds checks.
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    let magic = 0x81u8;
    let datatype = 0x00u8;
    magic.encode(buffer);
    self.code.encode(buffer);
    self.keylen.encode(buffer);
    self.extralen.encode(buffer);
    datatype.encode(buffer);
    self.status.encode(buffer);
    ( (
        self.get_bodylen() +
        self.get_keylen()  +
        self.get_extralen()
      ) as u32).encode(buffer);
    self.opaque.encode(buffer);
    self.cas.encode(buffer);
  }
}
/*
 * Nom parser
 */
named!(pub parse_res_header<ResHeader>, do_parse!(
  tag!(b"\x81")     >>
  o: opcode_parse   >>
  kl: be_u16        >>
  el: be_u8         >>
  tag!(b"\x00")     >>
  st: status_parse  >>
  bl: be_u32        >>
  op: be_u32        >>
  cas: be_u64       >>
  (
    ResHeader{
    code: o,
    extralen: el,
    status: st,
    keylen: kl,
    bodylen: (bl - (kl as u32 + el as u32)),
    opaque: op,
    cas: cas
  }
)));



/*
 *Request Packet
 */
/// I'm not writing this method out 3 times
#[inline(always)]
fn get_len(x: &Option<&[u8]>) -> usize {
  match x {
    &Option::None => 0usize,
    &Option::Some(ref b) => b.len(),
  }
}


/// Memcached Response Packet
///
/// The whole thing
#[derive(Clone,Debug)]
pub struct Response<'a> {
  header: ResHeader,
  extra: Option<&'a [u8]>,
  key: Option<&'a [u8]>,
  body: Option<&'a [u8]>
}
impl<'a> Response<'a> {
 
  /// Parse a full response. Internal Key/Extra/Body fields are borrowed. 
  pub fn parse(x: &'a [u8]) -> ParseResult<Response<'a>> {
    #[inline(always)]
    fn to_opt<'b>(z: &'b [u8]) -> Option<&'b [u8]> {
      if z.len() == 0 {
        None
      } else {
        Some(z)
      }
    }
    named!(parse_request<Response>, do_parse!(
      h: parse_res_header         >>
      e: take!(h.get_extralen())  >>
      k: take!(h.get_keylen())    >>
      b: take!(h.get_bodylen())   >>
      (Response{
        header: h,
        extra: to_opt(e),
        key: to_opt(k),
        body: to_opt(b)
      })
    ));
    ParseResult::from(parse_request(x))
  }
  /// Allocates a new buffer and encodes this packets contents into it.
  /// this method works out to a handful of `memcp` primatives and is
  /// fairly quick as their is no bounds checking (buffer length is
  /// asserted on construction).
  #[inline]
  pub fn encode_self(&self) -> Encoder {
    let mut e = Encoder::new(self);
    self.encode(&mut e);
    e
  }
  /// If you are using a slab to avoid making too many allocations
  /// this method will check check the `Vec<u8>` it is passed
  /// only reserving additional capacity if necessary. If the `Vec<u8>`
  /// has enough capacity no action is taken.
  #[inline]
  pub fn encode_into_buffer(&self, x: Vec<u8>) -> Encoder {
    let mut e = Encoder::from_vec(self, x);
    self.encode(&mut e);
    e
  }
  /// This interface does ABSOLUTELY NO verfication of the packet
  /// it is expected if you are calling this method you understand
  /// the memcached protocol and you are going to use this to generate
  /// a valid packet.
  ///
  /// The goal of this interface is to be fast. Encoding a packet
  /// with this interface + Encode trait involves very few branches
  ///
  /// Memcached only allows Keys that are ASCII and non-white space
  /// this interface does not do ANY assertions of this. Please be
  /// aware.
  #[inline]
  pub fn new( opcode: OpCode,status: StatusField,opaque: u32,cas: u64,extra: Option<&'a [u8]>,key: Option<&'a [u8]>,body: Option<&'a [u8]>) -> Response<'a> {
    let e = get_len(&extra);
    let k = get_len(&key);
    let b = get_len(&body);
    let bl = b + k + e;
    Response {
      header: ResHeader {
        code: opcode,
        status: status,
        extralen: e as u8,
        keylen: k as u16,
        bodylen: bl as u32,
        opaque: opaque,
        cas: cas
      },
      extra: extra,
      key: key,
      body: body
    }
  }
  /// Over write an existing request
  ///
  /// This is provided to allow for easier interfacing with SLAB's. The
  /// semantics of this method are identical to the above. The primary
  /// difference is this doesn't push ~100 bytes to the stack.
  ///
  /// This interface does ABSOLUTELY NO verfication of the packet
  /// it is expected if you are calling this method you understand
  /// the memcached protocol and you are going to use this to generate
  /// a valid packet.
  ///
  /// The goal of this interface is to be fast. Encoding a packet
  /// with this interface + Encode trait involves very few branches
  ///
  /// Memcached only allows Keys that are ASCII and non-white space
  /// this interface does not do ANY assertions of this. Please be
  /// aware.
  #[inline]
  pub fn rebuild(&mut self,opcode: OpCode,status: StatusField,opaque: u32,cas: u64,extra: Option<&'a [u8]>,key: Option<&'a [u8]>,body: Option<&'a [u8]>){
    use std::mem::replace;
    
    let e = get_len(&extra);
    let k = get_len(&key);
    let b = get_len(&body);
    let bl = b + k + e;
    self.header.code = opcode;
    self.header.status = status;
    self.header.extralen = e as u8;
    self.header.keylen = k as u16;
    self.header.bodylen = bl as u32;
    self.header.opaque = opaque;
    self.header.cas = cas;
    let _ = replace(&mut self.extra, extra);
    let _ = replace(&mut self.key, key);
    let _ = replace(&mut self.body, body);
  } 
  #[inline(always)]
  pub fn get_opcode(&self) -> OpCode {
    self.header.get_opcode()
  }
  #[inline(always)]
  pub fn get_opaque(&self) -> u32 {
    self.header.opaque
  } 
  #[inline(always)]
  pub fn get_cas(&self) -> u64 {
      self.header.cas
  }
  /// Check Status Field
  ///
  /// If the condition `StatusField::NoError` is set this
  /// will return `Ok(())`, if there is an error it will
  /// return it in `Err(StatusField::_)`
  ///
  /// All _standard_ error codes are implemented.
  #[inline(always)]
  pub fn check_status(&self) -> Result<(),StatusField> {
    self.header.check_status()
  }
  #[inline(always)]
  pub fn has_extra(&self) -> bool {
    self.extra.is_some()
  }
  #[inline(always)]
  pub fn get_extra(&'a self) -> Option<&'a [u8]> {
    self.extra
  }
  #[inline(always)]
  pub fn has_key(&self) -> bool {
    self.key.is_some()
  }
  #[inline(always)]
  pub fn get_key(&'a self) -> Option<&'a [u8]> {
    self.key
  }
  /// The standard states the key should be an ASCII compatible string
  /// so this method preforms that conversion without checking for
  /// correctness.
  ///
  /// This isnt a _problem_ as the key will be hash/stored as a byte
  /// buffer anyways.
  ///
  /// This really only opens the door to non standard things.
  #[inline(always)]
  pub fn get_key_str(&'a self) -> Option<&'a str> {
    use std::str::from_utf8_unchecked;
    unsafe{ self.key.map(|x| from_utf8_unchecked(x)) }
  }
  #[inline(always)]
  pub fn has_body(&self) -> bool {
    self.body.is_some()
  }
  #[inline(always)]
  pub fn get_body(&'a self) -> Option<&'a [u8]> {
    self.body
  }
  /// Consume this item and take ownership
  ///
  /// If a field is `Option::None` the resulting
  /// vector will be a `Vec::with_capacity(0)` which
  /// does not allocate. So this method can be
  /// cheap depending on the messages contents.
  #[inline]
  pub fn to_owned(self) -> OwnedResponse {
    fn to_vec(x: Option<&[u8]>) -> Vec<u8> {
      match x {
        Option::Some(ref b) => {
          let mut v = Vec::with_capacity(b.len());
          v.extend_from_slice(b);
          v
        },
        _ => Vec::with_capacity(0)
      }
    }
    OwnedResponse {
      body: to_vec(self.get_body()),
      key: to_vec(self.get_key()),
      extra: to_vec(self.get_extra()),
      header: self.header,
    }
  }
}
impl<'a> PacketVal for Response<'a> {
  /// Get size of Packet's Key Field
  #[inline(always)]
  fn get_keylen(&self) -> usize {
    self.header.keylen as usize
  }
  /// Get size of Packet's Body Field (Raw Data)
  #[inline(always)]
  fn get_bodylen(&self) -> usize {
    self.header.bodylen as usize
  }
  /// Get size of Packet's Extra Field (Flags, Arguments, Etc. command specific)
  #[inline(always)]
  fn get_extralen(&self) -> usize {
    self.header.extralen as usize
  }
}
impl<'a> Encoding for Response<'a> {
  /// Relatively fast method for encoding header
  ///
  /// If you avoid the `with::capacity` method for
  /// constructing `Encoder` this method is prefectly
  /// safe and will encode the packet header without
  /// any bounds checks.
  fn encode(&self, buffer: &mut Encoder) {
    self.header.encode(buffer);
    self.extra.encode(buffer);
    self.key.encode(buffer);
    self.body.encode(buffer);
  }
}

/// Clones Buffers
///
/// Like a response but all it's fields are owned
/// so there are now lifetimes to manage
/// but this also means you re-allocate AND copy
/// the body/key/extra buffers
pub struct OwnedResponse {
 header: ResHeader,
 pub extra: Vec<u8>,
 pub key: Vec<u8>,
 pub body: Vec<u8>
}
impl Encoding for OwnedResponse {
  /// Relatively fast method for encoding header
  ///
  /// If you avoid the `with::capacity` method for
  /// constructing `Encoder` this method is prefectly
  /// safe and will encode the packet header without
  /// any bounds checks.
  fn encode(&self, buffer: &mut Encoder) {
    self.header.encode(buffer);
    self.extra.encode(buffer);
    self.key.encode(buffer);
    self.body.encode(buffer);
  }
}
impl PacketVal for OwnedResponse {
  /// Get size of Packet's Key Field
  #[inline(always)]
  fn get_keylen(&self) -> usize {
    self.header.keylen as usize
  }
  /// Get size of Packet's Body Field (Raw Data)
  #[inline(always)]
  fn get_bodylen(&self) -> usize {
    self.header.bodylen as usize
  }
  /// Get size of Packet's Extra Field (Flags, Arguments, Etc. command specific)
  #[inline(always)]
  fn get_extralen(&self) -> usize {
    self.header.extralen as usize
  }
}
impl OwnedResponse {
  
  /// Reads a full packet and COPIES it's buffers into its own.
  /// Allocation is lazy. Fields that are not used are not allocated.
  /// Fields are not allocated WHILE parsing, only when complete.
  pub fn parse(x: &[u8]) -> ParseResult<Self> {
    #[inline(always)]
    fn from_opt(x: &[u8]) -> Vec<u8> {
      if x.len() != 0 {
        x.to_vec()
      } else {
        Vec::with_capacity(0)
      }
    }
    named!(parse_owned_response<OwnedResponse>, do_parse!(
      h: parse_res_header         >>
      e: take!(h.get_extralen())  >>
      k: take!(h.get_keylen())    >>
      b: take!(h.get_bodylen())   >>
      (OwnedResponse {
        header: h,
        extra: from_opt(e),
        key: from_opt(k),
        body: from_opt(b)
      })
    ));
    ParseResult::from(parse_owned_response(x))
  }
  
  /// Allocates a new buffer and encodes this packets contents into it.
  /// this method works out to a handful of `memcp` primatives and is
  /// fairly quick as their is no bounds checking (buffer length is
  /// asserted on construction).
  #[inline]
  pub fn encode_self(&self) -> Encoder {
    let mut e = Encoder::new(self);
    self.encode(&mut e);
    e
  }
  /// If you are using a slab to avoid making too many allocations
  /// this method will check check the `Vec<u8>` it is passed
  /// only reserving additional capacity if necessary. If the `Vec<u8>`
  /// has enough capacity no action is taken.
  #[inline]
  pub fn encode_into_buffer(&self, x: Vec<u8>) -> Encoder {
    let mut e = Encoder::from_vec(self, x);
    self.encode(&mut e);
    e
  }
  #[inline]
  pub fn new( opcode: OpCode,status: StatusField, opaque: u32,cas: u64,extra: Vec<u8>,key: Vec<u8>, body: Vec<u8>) -> Self {
    let e = extra.len();
    let k = key.len();
    let b = body.len();
    let bl = b + k + e;
    OwnedResponse {
      header: ResHeader {
        code: opcode,
        status: status,
        extralen: e as u8,
        keylen: k as u16,
        bodylen: bl as u32,
        opaque: opaque,
        cas: cas
      },
      extra: extra,
      key: key,
      body: body
    }
  }
  /// Over write an existing request
  ///
  /// This is provided to allow for easier interfacing with SLAB's. The
  /// semantics of this method are identical to the above. The primary
  /// difference is this doesn't push ~100 bytes to the stack.
  ///
  /// This interface does ABSOLUTELY NO verfication of the packet
  /// it is expected if you are calling this method you understand
  /// the memcached protocol and you are going to use this to generate
  /// a valid packet.
  ///
  /// The goal of this interface is to be fast. Encoding a packet
  /// with this interface + Encode trait involves very few branches
  ///
  /// Memcached only allows Keys that are ASCII and non-white space
  /// this interface does not do ANY assertions of this. Please be
  /// aware.
  #[inline]
  pub fn rebuild(&mut self, opcode: OpCode, status: StatusField, opaque: u32, cas: u64, extra: Vec<u8>, key: Vec<u8>, body: Vec<u8>){
    use std::mem::replace;
    
    let e = extra.len();
    let k = key.len();
    let b = body.len();
    let bl = b + k + e;
    self.header.code = opcode;
    self.header.status = status;
    self.header.extralen = e as u8;
    self.header.keylen = k as u16;
    self.header.bodylen = bl as u32;
    self.header.opaque = opaque;
    self.header.cas = cas;
    let _ = replace(&mut self.extra, extra);
    let _ = replace(&mut self.key, key);
    let _ = replace(&mut self.body, body);
  } 
  #[inline(always)]
  pub fn get_opcode(&self) -> OpCode {
    self.header.get_opcode()
  }
  #[inline(always)]
  pub fn get_opaque(&self) -> u32 {
    self.header.opaque
  } 
  #[inline(always)]
  pub fn get_cas(&self) -> u64 {
      self.header.cas
  }
  /// If the condition `StatusField::NoError` is set this
  /// will return `Ok(())`, if there is an error it will
  /// return it in `Err(StatusField::_)`
  ///
  /// All _standard_ error codes are implemented.
  #[inline(always)]
  pub fn check_status(&self) -> Result<(),StatusField> {
    self.header.check_status()
  }
  #[inline(always)]
  pub fn has_extra(&self) -> bool {
    self.extra.len() != 0
  }
  #[inline(always)]
  pub fn get_extra<'a>(&'a self) -> Option<&'a [u8]> {
    if self.has_extra() {
      Some(self.extra.as_slice())
    } else {
      None
    }
  }
  #[inline(always)]
  pub fn has_key(&self) -> bool {
    self.key.len() != 0
  }
  #[inline(always)]
  pub fn get_key<'a>(&'a self) -> Option<&'a [u8]> {
    if self.has_key() {
      Some(self.key.as_slice())
    } else {
      None
    }
  }
  /// The standard states the key should be an ASCII compatible string
  /// so this method preforms that conversion without checking for
  /// correctness.
  ///
  /// This isnt a _problem_ as the key will be hash/stored as a byte
  /// buffer anyways.
  ///
  /// This really only opens the door to non standard things.
  #[inline(always)]
  pub fn get_key_str<'a>(&'a self) -> Option<&'a str> {
    use std::str::from_utf8_unchecked;
    unsafe{ self.get_key().map(|x| from_utf8_unchecked(x)) }
  }
  #[inline(always)]
  pub fn has_body(&self) -> bool {
    self.body.len() != 0
  }
  #[inline(always)]
  pub fn get_body<'a>(&'a self) -> Option<&'a [u8]> {
    if self.has_body() {
      Some(self.body.as_slice())
    } else {
      None
    }
  }
}


