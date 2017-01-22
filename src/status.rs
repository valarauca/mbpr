use super::{Encoding,ResponseStatus};
use super::nom::{
  IResult,
  ErrorKind,
  be_u16
};

use std::mem;


/// Status Field
///
/// Used in Response Packets if an error occured
#[repr(u16)]
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum StatusField {
  NoError = 0,  
  KeyNotFound = 1,
  KeyExists = 2,
  ValueTooLarge = 3,
  InvalidArguments = 4,
  ItemNotStored = 5,
  IncrDecrNonNumeric = 6,
  VBucketNotHere = 7,
  AuthError = 8,
  AuthContinue = 9,
  UnknownCommand = 0x81,
  OutOfMemory = 0x82,
  NotSupported = 0x83,
  InternalError = 0x84,
  Busy = 0x85,
  TemporaryFailure = 0x86
}
impl ResponseStatus for StatusField {
  /// Base implementatin of status method
  ///
  /// This just check if the status field
  /// is `StatusField::NoError` or `0x0000u16`
  /// in the packet.
  ///
  /// #Result::Ok(())
  ///
  /// The packet is good
  ///
  /// #Result::Err(StatusField)
  ///
  /// The packet is bad. The StatusField value can
  /// never be `StatusField::NoError`
  #[inline(always)]
  fn status(&self) -> Result<(), StatusField> {
    match *self {
      StatusField::NoError => Ok(()),
      x => Err(x)
    }
  }
}
impl Into<u16> for StatusField {
  #[inline(always)]
  fn into(self) -> u16 {
    unsafe{ mem::transmute(self) }
  }
}
impl Encoding for StatusField {
  /// Encodes value into packet
  #[inline(always)]
  fn encode(&self, buffer: &mut Vec<u8>) {
    let val: u16 = self.clone().into();
    val.encode(buffer);
  }
}

/// Widly unsafe method to get StatusField type
#[inline(always)]
fn from_u16(x: u16) -> StatusField {
  unsafe{ mem::transmute(x) }
}

/// Checks if the status u16 is a real value
#[inline(always)]
fn valid_status(val: u16) -> bool {
    val <= 9
      ||
    (val >= 0x81 && val <= 0x86)
}

/// Parses a StatusField from a packet
///
/// On an unknown opcode this will return
/// `IResult::Error(ErrorKind::Custom(0x83))`
/// which is memcached error for `Not Supported`
#[allow(dead_code)]
#[inline(always)]
pub fn status_parse<'a>(i: &'a [u8])
-> IResult<&'a [u8], StatusField> {
  match be_u16(i) {
    IResult::Done(rem,val) => if valid_status(val) {
        IResult::Done(rem,from_u16(val))
      } else {
        IResult::Error(ErrorKind::Custom(0x83))
    },
    IResult::Error(e) => IResult::Error(e),
    IResult::Incomplete(n) => IResult::Incomplete(n)
  }
}

/*
 *Tests below here
 */
macro_rules! ot {
  ($a: expr, $b: ident) => {
    let value: u16 = $a;
    let sf: StatusField = StatusField::$b;
    assert!(valid_status(value));
    assert_eq!(from_u16(value), sf);
    let mut v = Vec::with_capacity(20);
    sf.encode(&mut v);
    v.push(0);
    assert_eq!(v.len(), 3);
    let (rem, dut) = status_parse(v.as_slice()).unwrap();
    assert_eq!(rem.len(), 1);
    assert_eq!(rem, b"\x00");
    assert_eq!(dut, sf);
    if sf == StatusField::NoError {
      assert!(sf.status().is_ok());
    } else {
      assert_eq!(sf.status().err(), Option::Some(sf));
    }
  }
}
macro_rules! bt {
  ($a: expr) => {
    let val: u16 = $a;
    assert!(  ! valid_status(val));
  }
}
#[test]
fn test_status_field() {
  ot!(0, NoError);
  ot!(1, KeyNotFound);
  ot!(2, KeyExists);
  ot!(3, ValueTooLarge);
  ot!(4, InvalidArguments);
  ot!(5, ItemNotStored);
  ot!(6, IncrDecrNonNumeric);
  ot!(7, VBucketNotHere);
  ot!(8, AuthError);
  ot!(9, AuthContinue);
  ot!(0x81, UnknownCommand);
  ot!(0x82, OutOfMemory);
  ot!(0x83, NotSupported);
  ot!(0x84, InternalError);
  ot!(0x85, Busy);
  ot!(0x86, TemporaryFailure);

  for code in 10u16..0x81u16 {
    bt!(code);
  }

  for code in 0x87u16..0xFFFFu16 {
    bt!(code);
  }

  bt!(0xFFFFu16);
}






























