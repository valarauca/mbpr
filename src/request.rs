use super::{
  Encoding, 
  Op,
  PacketVal, 
  Packet
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
impl Op for ReqHeader {
  #[inline(always)]
  fn get_opcode(&self) -> OpCode {
    self.code.get_opcode()
  }
}
impl PacketVal for ReqHeader {
  pv_builder!(get_keylen, keylen);
  pv_builder!(get_extralen, extralen);
  pv_builder!(get_bodylen, bodylen);
  pv_builder!(get_opaque, opaque);
  pv_builder!(get_cas, cas);
}
impl Encoding for ReqHeader {
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
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
/*
 * Nom parser
 */
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
named!(pub parse_request<Request>, do_parse!(
  h: parse_req_header         >>
  e: take!(h.get_extralen())  >>
  k: take!(h.get_keylen())    >>
  b: take!(h.get_bodylen())   >>
  (Request{
    header: h,
    extra: if e.len() == 0 { None } else {Some(e)},
    key: if k.len() == 0 { None } else {Some(k) },
    body: if b.len() == 0 {None } else {Some(b) }
  })
));
impl<'a> Op for Request<'a> {
  #[inline(always)]
  fn get_opcode(&self) -> OpCode {
    self.header.get_opcode()
  }
} 
impl<'a> PacketVal for Request<'a> {
  pv_builder!(@P get_keylen);
  pv_builder!(@P get_extralen);
  pv_builder!(@P get_bodylen);
  pv_builder!(@P get_opaque);
  pv_builder!(@P get_cas);
}
impl<'a> Encoding for Request<'a> {
  /// Encode a packet
  fn encode(&self, buffer: &mut Vec<u8>) {
    self.header.encode(buffer);
    self.extra.encode(buffer);
    self.key.encode(buffer);
    self.body.encode(buffer);
  }
}
impl<'a> Packet<'a> for Request<'a> {
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
impl<'a> Request<'a> {
  #[inline(always)]
  pub fn get_vbucket_id(&self) -> usize {
    self.header.vbucket_id as usize
  }
}


/*
 *
 * TEST!
 *
 */

#[allow(dead_code)]
const GETPACKET: &'static [u8] = b"\x80\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x65\x6C\x6C\x6F";


#[test]
fn get_parse() {
  assert_eq!(GETPACKET.len(), 29);
  let (_,p) = parse_request(GETPACKET).unwrap();
  assert_eq!(p.get_opcode(), OpCode::Get);
  assert_eq!(p.get_keylen(), 5);
  assert_eq!(p.get_extralen(), 0);
  assert_eq!(p.get_bodylen(), 0);
  assert_eq!(p.get_opaque(), 0);
  assert_eq!(p.get_cas(), 0);
  assert_eq!(p.total_len(), 29);
  assert!(  ! p.has_extra());
  assert!(  ! p.has_body());
  assert!(p.has_key());
  assert_eq!(p.get_extra(), Option::None);
  assert_eq!(p.get_body(), Option::None);
  assert_eq!(p.get_key().unwrap(), b"\x48\x65\x6C\x6C\x6F");

  let mut v = Vec::with_capacity(30);
  p.encode(&mut v);
  assert_eq!(v.len(), GETPACKET.len());
  assert_eq!(v.as_slice(), GETPACKET);
}

#[allow(dead_code)]
const ADDPACKET: &'static [u8] = b"\x80\x02\x00\x05\x08\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x0e\x10\x48\x65\x6C\x6C\x6F\x57\x6F\x72\x6C\x64";

#[test]
fn add_parse() {
  assert_eq!(ADDPACKET.len(), 42);
  let (_,p) = parse_request(ADDPACKET).unwrap();
  assert_eq!(p.get_opcode(), OpCode::Add);
  assert_eq!(p.get_keylen(), 5);
  assert_eq!(p.get_extralen(), 8);
  assert_eq!(p.get_bodylen(), 5);
  assert_eq!(p.get_opaque(), 0);
  assert_eq!(p.get_cas(), 0);
  assert_eq!(p.total_len(),42);
  assert!(p.has_extra());
  assert!(p.has_body());
  assert!(p.has_key());
  assert_eq!(p.get_extra().unwrap(),
    b"\xDE\xAD\xBE\xEF\x00\x00\x0E\x10");
  assert_eq!(p.get_body().unwrap(), b"\x57\x6F\x72\x6C\x64");
  assert_eq!(p.get_key().unwrap(), b"\x48\x65\x6C\x6C\x6F");

  let mut v = Vec::with_capacity(50);
  p.encode(&mut v);
  assert_eq!(v.len(), ADDPACKET.len());
  for i in 0..42 {
    let a = v[i];
    let b = ADDPACKET[i];
    if a != b {
      panic!("Error at index {:?} on {:?} != {:?}",i,a,b);
    }
  }
}

#[allow(dead_code)]
const DELETEP: &'static [u8] =b"\x80\x04\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x65\x6C\x6C\x6F";

#[test]
fn delete_parse() {
  assert_eq!(DELETEP.len(), 29);
  let (_,p) = parse_request(DELETEP).unwrap();
  assert_eq!(p.get_opcode(), OpCode::Delete);
  assert_eq!(p.get_keylen(), 5);
  assert_eq!(p.get_extralen(),0);
  assert_eq!(p.get_bodylen(), 0);
  assert_eq!(p.get_opaque(), 0);
  assert_eq!(p.get_cas(), 0);
  assert_eq!(p.total_len(), 29);
  assert!(  !   p.has_extra());
  assert!(  !   p.has_body());
  assert!(p.has_key());
  assert_eq!(p.get_key().unwrap(), b"\x48\x65\x6C\x6C\x6F");

  let mut v = Vec::with_capacity(50);
  p.encode(&mut v);
  assert_eq!(v.len(), DELETEP.len());
  for i in 0..29 {
    let a = v[i];
    let b = DELETEP[i];
    if a != b {
      panic!("Error at index {:?} on {:?} != {:?}",i,a,b);
    }
  }
}

























































































