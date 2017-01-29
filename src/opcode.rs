use super::{
  Encoding,
  Encoder
};
use super::nom::{
  IResult, 
  ErrorKind
};
use std::mem;

/// Memcache Opcodes
///
/// All valid commands are supported
#[repr(u8)]
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum OpCode {
  Get = 0x00,
  Set = 0x01,
  Add = 0x02,
  Replace = 0x03,
  Delete = 0x04,
  Increment = 0x05,
  Decrement = 0x06,
  Quit = 0x07,
  Flush = 0x08,
  GetQ = 0x09,
  Nop = 0x0A,
  Version = 0x0B,
  GetK = 0x0C,
  GetKQ = 0x0D,
  Append = 0x0E,
  Prepare = 0x0F,
  Stat = 0x10,
  SetQ = 0x11,
  AddQ = 0x12,
  ReplaceQ = 0x13,
  DeleteQ = 0x14,
  IncrementQ = 0x15,
  DecrementQ = 0x16,
  QuitQ = 0x17,
  FlushQ = 0x18,
  AppendQ = 0x19,
  PrependQ = 0x1A,
  Verbosity = 0x1B,
  Touch = 0x1C,
  GAT = 0x1D,
  GATQ = 0x1E,
  
  SASLlistmech = 0x20,
  SASLAuth = 0x21,
  SASLStep = 0x22,
  
  RGet = 0x30,
  RSet = 0x31,
  RSetQ = 0x32,
  RAppend = 0x33,
  RAppendQ = 0x34,
  RPrepend = 0x35,
  RPrependQ = 0x36,
  RDelete = 0x37,
  RDeleteQ = 0x38,
  RIncr = 0x39,
  RIncrQ = 0x3A,
  RDecr = 0x3B,
  RDecrQ = 0x3C,
  SetVBucket = 0x3D,
  GetVBucket = 0x3E,
  DelVBucket = 0x3F,
  TAPConnect = 0x40,
  TAPMutate = 0x41,
  TAPDelete = 0x42,
  TAPFlush = 0x43,
  TAPOpaque = 0x44,
  TAPVBucketSet = 0x45,
  TAPCheckpointStart = 0x46,
  TAPCheckpointEnd = 0x47
}
impl Into<u8> for OpCode {
  
  /// Converts an OpCode into it's byte code (at no
  /// computation cost) for encoding
  #[inline(always)]
  fn into(self) -> u8 {
    unsafe{ 
      mem::transmute(self)
    }
  }
}
impl Encoding for OpCode {
  /// Writes opcode into `buffer[1]`
  #[inline(always)]
  fn encode(&self, buffer: &mut Encoder) {
    let val: u8 = self.clone().into();
    val.encode(buffer);
  }
}

/// Widly unsafe method for converting a byte to an opcode
#[inline(always)]
fn from_u8(x: u8) -> OpCode {
    unsafe{
      mem::transmute(x)
    }
}

/// Parses an OpCode from a packet.
///
/// On `IResult::Error(ErrorKind::Custom(_))` it
/// returns memcached Unknown Command Error error
/// code to represent the OpCode is not recongized
#[allow(dead_code)]
#[inline(always)]
pub fn opcode_parse<'a>(i: &'a [u8])
-> IResult<&'a [u8], OpCode>
{
  let byte = i[0].clone();
  if byte <= 0x1E {
    return IResult::Done(&i[1..], from_u8(byte));
  }
  if byte >= 0x30 && byte <= 0x47 {
    return IResult::Done(&i[1..], from_u8(byte));
  }
  if byte >= 0x20 && byte <= 0x22 {
    return IResult::Done(&i[1..], from_u8(byte));
  }
  //memcached's Unknown Command Error
  IResult::Error(ErrorKind::Custom(0x81))
}



#[test]
fn test_opcode_decode() {

use super::{Fault,ParseResult};
/*
 *Abstract test boiler plate
 */
macro_rules! ot {
  ($a: expr, $b: ident) => {
    let dut = OpCode::$b;
    let encode: u8 = dut.into();
    assert_eq!($a, encode);
    assert_eq!(from_u8($a), dut);
    let v: Vec<u8> = vec![ $a, 0x01u8];
    let p = ParseResult::from(opcode_parse(v.as_slice())); 
    assert!(p.is_ok());
    let parse_out = match p {
      ParseResult::Ok(x) => x,
      ParseResult::Err(e) => panic!("Value {:?} should be a valid opcode not {:?}",encode, e)
    };
    assert_eq!(parse_out, dut);
  }
}

/*
 * Ensures non-ops are parsed as such
 */
macro_rules! bad_code {
  ($a: expr) => {
    let dut: u8 = $a;
    let v: Vec<u8> = vec![ dut, 0x01 ];
    let p = ParseResult::from(opcode_parse(v.as_slice()));
    assert!(p.is_err());
    match p {
      ParseResult::Err(Fault::BadOpCode) => { },
      ParseResult::Err(x) => panic!("Opcode {:?} should be `Fault::BadOpCode` not {:?}", dut, x),
      _ => unreachable!()
    };
  }
}

  /*
   * Test opcode block
   */
  ot!(0x00, Get);
  ot!(0x01, Set);
  ot!(0x02, Add);
  ot!(0x03, Replace);
  ot!(0x04, Delete);
  ot!(0x05, Increment);
  ot!(0x06, Decrement);
  ot!(0x07, Quit);
  ot!(0x08, Flush);
  ot!(0x09, GetQ);
  ot!(0x0A, Nop);
  ot!(0x0B, Version);
  ot!(0x0C, GetK);
  ot!(0x0D, GetKQ);
  ot!(0x0E, Append);
  ot!(0x0F, Prepare);
  ot!(0x10, Stat);
  ot!(0x11, SetQ);
  ot!(0x12, AddQ);
  ot!(0x13, ReplaceQ);
  ot!(0x14, DeleteQ);
  ot!(0x15, IncrementQ);
  ot!(0x16, DecrementQ);
  ot!(0x17, QuitQ);
  ot!(0x18, FlushQ);
  ot!(0x19, AppendQ);
  ot!(0x1A, PrependQ);

  /*
   * v1.5 extenesions (not finalized)
   */
  ot!(0x1B, Verbosity);
  ot!(0x1C, Touch);
  ot!(0x1D, GAT);
  ot!(0x1E, GATQ);
 
  /*
   * SASL stuff
   */
  ot!(0x20, SASLlistmech);
  ot!(0x21, SASLAuth);
  ot!(0x22, SASLStep);

  /*
   * Normal block
   */
  ot!(0x30, RGet);
  ot!(0x31, RSet);
  ot!(0x32, RSetQ);
  ot!(0x33, RAppend);
  ot!(0x34, RAppendQ);
  ot!(0x35, RPrepend);
  ot!(0x36, RPrependQ);
  ot!(0x37, RDelete);
  ot!(0x38, RDeleteQ);
  ot!(0x39, RIncr);
  ot!(0x3A, RIncrQ);
  ot!(0x3B, RDecr);
  ot!(0x3C, RDecrQ);
  
  /*
   * v1.6 extensions (not finalized)
   */
  ot!(0x3D, SetVBucket);
  ot!(0x3E, GetVBucket);
  ot!(0x3F, DelVBucket);
  ot!(0x40, TAPConnect);
  ot!(0x41, TAPMutate);
  ot!(0x42, TAPDelete);
  ot!(0x43, TAPFlush);
  ot!(0x44, TAPOpaque);
  ot!(0x45, TAPVBucketSet);
  ot!(0x46, TAPCheckpointStart);
  ot!(0x47, TAPCheckpointEnd);


  /*
   * Ensure bad codes are errors
   */

  // lonely code between standard stuff
  // and SASL
  bad_code!(0x1F);
  
  //block between SASL and normal block
  for code in 0x23u8..0x30u8 {
    bad_code!(code);
  }

  //block to end
  for code in 0x48u8..0xFFu8 {
    bad_code!(code);
  }

  //rust loops are range inclusive
  bad_code!(0xFFu8);
}
