//everything inside a nom macro is dead code
#![allow(dead_code)]

use super::{
  ParseResult,
  Encoding,
  PacketVal,
  Encoder
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


/// Memcached Request Packet Header
///
/// This is the first 24 bytes of the packet
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ReqHeader {
  code: OpCode,
  extralen: u8,
  vbucket_id: u16,
  keylen: u16,
  bodylen: u32,
  opaque: u32,
  cas: u64
}
impl ReqHeader {
  /// Parse a request header
  #[inline]
  pub fn parse(buffer: &[u8]) -> ParseResult<Self> {
    ParseResult::from(parse_req_header(buffer))
  }
  #[inline(always)]
  pub fn get_opaque(&self) -> u32 {
      self.opaque
  }
  #[inline(always)]
  pub fn get_cas(&self) -> u64 {
      self.cas
  }
  #[inline(always)]
  pub fn get_opcode(&self) -> OpCode {
    self.code
  }
  #[inline(always)]
  pub fn get_vbucket_id(&self) -> u16 {
    self.vbucket_id
  }
}
impl PacketVal for ReqHeader {
  #[inline(always)]
  fn get_keylen(&self) -> usize {
      self.keylen as usize
  }
  #[inline(always)]
  fn get_bodylen(&self) -> usize {
      self.bodylen as usize
  }
  #[inline(always)]
  fn get_extralen(&self) -> usize {
      self.extralen as usize
  }
}
impl Encoding for ReqHeader {
  /// Fast encoding method
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    let magic = 0x80u8;
    let datatype = 0x00u8;
    magic.encode(buffer);
    self.code.encode(buffer);
    self.keylen.encode(buffer);
    self.extralen.encode(buffer);
    datatype.encode(buffer);
    self.vbucket_id.encode(buffer);
    ( (
        self.get_bodylen() +
        self.get_keylen()  +
        self.get_extralen()
      ) as u32).encode(buffer);
    self.opaque.encode(buffer);
    self.cas.encode(buffer);
  }
}

///Parse only the header
named!(pub parse_req_header<ReqHeader>, do_parse!(
  tag!(b"\x80")     >>
  o: opcode_parse   >>
  kl: be_u16        >>
  el: be_u8         >>
  tag!(b"\x00")     >>
  vb_id: be_u16     >>
  bl: be_u32        >>
  op: be_u32        >>
  cas: be_u64       >>
  (
    ReqHeader{
    code: o,
    extralen: el,
    vbucket_id: vb_id,
    keylen: kl,
    bodylen: bl - (kl as u32 + el as u32),
    opaque: op,
    cas: cas
  }
)));


#[inline(always)]
fn get_len(x: &Option<&[u8]>) -> usize {
  match x {
    &Option::Some(ref b) => b.len(),
    _ => 0
  }
}

/*
 *Request Packet
 */

/// Memcached Request Packet
///
/// The whole thing
#[derive(Clone,Debug)]
pub struct Request<'a> {
  header: ReqHeader,
  extra: Option<&'a [u8]>,
  key: Option<&'a [u8]>,
  body: Option<&'a [u8]>
}
impl<'a> Request<'a> {
  
  /// Parse and borrow a packet from a buffer
  pub fn parse(x: &'a [u8]) -> ParseResult<Self> {
    
    #[inline(always)]
    fn to_opt<'b>(z: &'b [u8]) -> Option<&'b [u8]> {
      if z.len() == 0 {
        None
      } else {
        Some(z)
      }
    }
    named!(parse_request<Request>, do_parse!(
      h: parse_req_header         >>
      e: take!(h.get_extralen())  >>
      k: take!(h.get_keylen())    >>
      b: take!(h.get_bodylen())   >>
      (Request{
        header: h,
        extra: to_opt(e),
        key: to_opt(k),
        body: to_opt(b)
      })
    ));
    ParseResult::from(parse_request(x))
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
  pub fn new( opcode: OpCode, vbucket: u16, opaque: u32,cas: u64,extra: Option<&'a [u8]>,key: Option<&'a [u8]>,body: Option<&'a [u8]>) -> Request<'a> {
    let e = get_len(&extra);
    let k = get_len(&key);
    let b = get_len(&body);
    let bl = b + k + e;
    Request {
      header:ReqHeader {
        code: opcode,
        vbucket_id: vbucket,
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
  pub fn rebuild(&mut self,opcode: OpCode, vbucket: u16, opaque: u32,cas: u64,extra: Option<&'a [u8]>,key: Option<&'a [u8]>,body: Option<&'a [u8]>){
    use std::mem::replace;
    
    let e = get_len(&extra);
    let k = get_len(&key);
    let b = get_len(&body);
    let bl = b + k + e;
    self.header.code = opcode;
    self.header.vbucket_id = vbucket;
    self.header.extralen = e as u8;
    self.header.keylen = k as u16;
    self.header.bodylen = bl as u32;
    self.header.opaque = opaque;
    self.header.cas = cas;
    let _ = replace(&mut self.extra, extra);
    let _ = replace(&mut self.key, key);
    let _ = replace(&mut self.body, body);
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
  #[inline(always)]
  pub fn get_vbucket_id(&self) -> u16 {
    self.header.vbucket_id
  }
  #[inline(always)]
  pub fn has_extra(&self) -> bool {
    self.extra.is_some()
  }
  #[inline(always)]
  pub fn has_key(&self) -> bool {
    self.key.is_some()
  }
  #[inline(always)]
  pub fn get_extra(&'a self) -> Option<&'a [u8]> {
    self.extra
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
  pub fn to_owned(self) -> OwnedRequest {
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
    OwnedRequest {
      body: to_vec(self.get_body()),
      key: to_vec(self.get_key()),
      extra: to_vec(self.get_extra()),
      header: self.header,
    }
  }
}
impl<'a> PacketVal for Request<'a> {
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
impl<'a> Encoding for Request<'a> {
  /// Encode a packet
  fn encode(&self, buffer: &mut Encoder) {
    self.header.encode(buffer);
    self.extra.encode(buffer);
    self.key.encode(buffer);
    self.body.encode(buffer);
  }
}

/// Clones Buffers
///
/// This behaves identical to Request other then the fact
/// that the internal `body`/`key`/`extra` fields are owned
/// vectors NOT borrowed slices. 
///
/// This makes life a lot easier when working with the borrow
/// checker, and concurrent programming.
#[derive(Clone)]
pub struct OwnedRequest {
  header: ReqHeader,
  pub key: Vec<u8>,
  pub extra: Vec<u8>,
  pub body: Vec<u8>
}
impl OwnedRequest {
  
  /// Reads a full packet and COPIES it's buffers into its own.
  /// Allocation is lazy. Fields that are not used are not allocated.
  /// Fields are not allocated WHILE parsing, only when complete.
  pub fn parse(x: &[u8]) -> ParseResult<Self> {
    named!(parse_owned_request<OwnedRequest>, do_parse!(
      h: parse_req_header         >>
      e: take!(h.get_extralen())  >>
      k: take!(h.get_keylen())    >>
      b: take!(h.get_bodylen())   >>
      (OwnedRequest{
        header: h,
        extra: if e.len() == 0 { Vec::with_capacity(0) } else {e.to_vec()},
        key: if k.len() == 0 { Vec::with_capacity(0) } else { k.to_vec() },
        body: if b.len() == 0 { Vec::with_capacity(0) } else { b.to_vec() }
      })
    ));
    ParseResult::from(parse_owned_request(x))
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
  pub fn new(opcode: OpCode, vbucket: u16, opaque: u32, cas: u64, extra: Vec<u8>, key: Vec<u8>, body: Vec<u8>) -> Self {
    let e = extra.len();
    let k = key.len();
    let b = body.len();
    let bl = b + k + e;
    OwnedRequest {
      header:ReqHeader {
        code: opcode,
        vbucket_id: vbucket,
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
  pub fn rebuild(&mut self, opcode: OpCode, vbucket: u16, opaque: u32, cas: u64, extra: Vec<u8>, key: Vec<u8>, body: Vec<u8>){
    use std::mem::replace;
    
    let e = extra.len();
    let k = key.len();
    let b = body.len();
    let bl = b + k + e;
    self.header.code = opcode;
    self.header.vbucket_id = vbucket;
    self.header.extralen = e as u8;
    self.header.keylen = k as u16;
    self.header.bodylen = bl as u32;
    self.header.opaque = opaque;
    self.header.cas = cas;
    let _ = replace(&mut self.extra, extra);
    let _ = replace(&mut self.key, key);
    let _ = replace(&mut self.body, body);
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
  #[inline(always)]
  pub fn get_opcode(&self) -> OpCode {
    self.header.code
  }
  #[inline(always)]
  pub fn get_opaque(&self) -> u32 {
    self.header.opaque
  }
  #[inline(always)]
  pub fn get_cas(&self) -> u64 {
    self.header.cas
  }
  #[inline(always)]
  pub fn get_vbucket_id(&self) -> u16 {
    self.header.vbucket_id
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
impl PacketVal for OwnedRequest {
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
impl Encoding for OwnedRequest {
  /// Encode a packet
  fn encode(&self, buffer: &mut Encoder) {
    self.header.encode(buffer);
    self.extra.encode(buffer);
    self.key.encode(buffer);
    self.body.encode(buffer);
  }
}

  
