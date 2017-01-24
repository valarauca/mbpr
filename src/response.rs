use super::{
  Encoding,
  Op,
  PacketVal,
  Packet,
  ResponseStatus
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
macro_rules! pv_builder {
  (@P $name: ident) => {
    #[allow(dead_code)]
    #[inline(always)]
    fn $name(&self) -> usize {
      self.header.$name()
    }
  };
  ($name: ident, $field: ident) => {
    #[allow(dead_code)]
    #[inline(always)]
    fn $name(&self) -> usize {
      self.$field.clone() as usize
    }
  };
}

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
impl Op for ResHeader {
  #[inline(always)]
  fn get_opcode(&self) -> OpCode {
    self.code.get_opcode()
  }
}
impl PacketVal for ResHeader {
  pv_builder!(get_keylen, keylen);
  pv_builder!(get_extralen, extralen);
  pv_builder!(get_bodylen, bodylen);
  pv_builder!(get_opaque, opaque);
  pv_builder!(get_cas, cas);
}
impl ResponseStatus for ResHeader {
    #[inline(always)]
    fn status(&self) -> Result<(),StatusField> {
        self.status.status()
    }
}
impl Encoding for ResHeader {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    let magic = 0x80u8;
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
  st: status_parse     >>
  bl: be_u32        >>
  op: be_u32        >>
  cas: be_u64       >>
  (
    ResHeader{
    code: o,
    extralen: el,
    status: st,
    keylen: kl,
    bodylen: bl - (kl as u32 + el as u32),
    opaque: op,
    cas: cas
  }
)));

/*
 *Request Packet
 */

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
named!(pub parse_request<Response>, do_parse!(
  h: parse_res_header         >>
  e: take!(h.get_extralen())  >>
  k: take!(h.get_keylen())    >>
  b: take!(h.get_bodylen())   >>
  (Response{
    header: h,
    extra: if e.len() == 0 { None } else {Some(e)},
    key: if k.len() == 0 { None } else {Some(k) },
    body: if b.len() == 0 {None } else {Some(b) }
  })
));
impl<'a> ResponseStatus for Response<'a> {
    #[inline(always)]
    fn status(&self) -> Result<(),StatusField> {
        self.header.status()
    }
}
impl<'a> Op for Response<'a> {
  #[inline(always)]
  fn get_opcode(&self) -> OpCode {
    self.header.get_opcode()
  }
}
impl<'a> PacketVal for Response<'a> {
  pv_builder!(@P get_keylen);
  pv_builder!(@P get_extralen);
  pv_builder!(@P get_bodylen);
  pv_builder!(@P get_opaque);
  pv_builder!(@P get_cas);
}
impl<'a> Encoding for Response<'a> {
  /// Encode a packet
  fn encode(&self, buffer: &mut Vec<u8>) {
    self.header.encode(buffer);
    self.extra.encode(buffer);
    self.key.encode(buffer);
    self.body.encode(buffer);
  }
}
impl<'a> Packet<'a> for Response<'a> {
  #[inline(always)]
  fn has_extra(&self) -> bool {
    self.extra.is_some()
  }
  #[inline(always)]
  fn has_key(&self) -> bool {
    self.key.is_some()
  }
  #[inline(always)]
  fn has_body(&self) -> bool {
    self.body.is_some()
  }

  #[inline(always)]
  fn get_extra(&'a self) -> Option<&'a [u8]> {
    self.extra
  }
  #[inline(always)]
  fn get_key(&'a self) -> Option<&'a [u8]> {
    self.key
  }
  #[inline(always)]
  fn get_body(&'a self) -> Option<&'a [u8]> {
    self.body
  }
}



/*
 *
 * TEST!
 *
 */
