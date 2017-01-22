use super::{Encoding, Op};
use super::nom::{
  IResult, 
  ErrorKind
};
use std::mem;

/// Memcache Opcodes
///
/// v1.6 extensions not supported
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
  RDecrQ = 0x3C
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
  fn encode(&self, buffer: &mut Vec<u8>) {
    let val: u8 = self.clone().into();
    val.encode(buffer);
  }
}
impl Op for OpCode {
  #[inline(always)]
  fn get_opcode(&self) -> OpCode {
    self.clone()
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
  if byte <= 0x1A {
    return IResult::Done(&i[1..], from_u8(byte));
  }
  if byte >= 0x030 && byte <= 0x3C {
    return IResult::Done(&i[1..], from_u8(byte));
  }
  //memcached's Unknown Command Error
  IResult::Error(ErrorKind::Custom(0x81))
}


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
    let (_,parse_out) = opcode_parse(v.as_slice()).unwrap();
    assert_eq!(parse_out, dut);
  }
}

/*
 * Ensures non-ops are parsed as such
 */
macro_rules! bad_code {
  ($a: expr) => {
    let v: Vec<u8> = vec![ $a, 0x01 ];
    match opcode_parse(v.as_slice()) {
      IResult::Error(ErrorKind::Custom(0x81)) => { },
      x => panic!("Bad input {:?} on {:?} should have error", x, $a)
    };
  }
}

#[test]
fn test_opcode_decode() {

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

  //test bad values
  for i in 0x1Bu8..0x30u8 {
    let val: u8 = i.clone();
    bad_code!(val);
  }

  //test rest of values
  for i in 0x3Du8..0xFFu8 {
    let val: u8 = i.clone();
    bad_code!(val);
  }

  //ensure last value is tested
  bad_code!(0xFFu8);
}
