
extern crate mbpr;
use mbpr::*;




/*
 *
 *
 * Assertions about ReqHeader
 *
 *
 *
 */
fn test_req_header(msg: &[u8], opaque: u32, cas: u64, code: OpCode, vbucket: u16, key: usize, extra: usize, body: usize, total: usize) {
  let packet: ReqHeader = match ReqHeader::parse(msg) {
    ParseResult::Ok(x) => x,
    ParseResult::Err(e) => panic!("ReqHeader::parse failed with {:?}",e)
  };
  assert_eq!(packet.get_opcode(), code);
  assert_eq!(packet.get_keylen(), key);
  assert_eq!(packet.get_extralen(), extra);
  assert_eq!(packet.get_vbucket_id(), vbucket);
  assert_eq!(packet.get_bodylen(), body);
  assert_eq!(packet.total_len(), total);
  assert_eq!(packet.get_opaque(), opaque);
  assert_eq!(packet.get_cas(), cas);
  let mut e = unsafe{ Encoder::with_capacity(4096) };
  packet.encode(&mut e);
  assert_eq!(e.len(), 24);
  assert_eq!(e.as_slice(), &msg[0..24]);
}
fn test_req_header_fail(msg: &[u8], fault: Fault) {
  match ReqHeader::parse(msg) {
    ParseResult::Ok(_) => panic!("Parsing should not succeed ... expected error code {:?}", fault),
    ParseResult::Err(e) => if e != fault {
        panic!("Parsing failed with {:?} ... expected {:?}", e, fault);
      } else {
        assert!(true);
      }
  };
}




/*
 *
 *
 * Assertions about ResHeader
 *
 *
 *
 */
fn test_res_header(msg: &[u8], opaque: u32, cas: u64, code: OpCode, status: StatusField, key: usize, extra: usize, body: usize, total: usize) {
  let packet: ResHeader = match ResHeader::parse(msg) {
    ParseResult::Ok(x) => x,
    ParseResult::Err(e) => panic!("ResHeader::parse failed with {:?}",e)
  };
  assert_eq!(packet.get_opaque(), opaque);
  assert_eq!(packet.get_cas(), cas);
  assert_eq!(packet.get_opcode(), code);
  match (packet.check_status(), status.check_status()) {
    (Ok(()), Ok(())) => { },
    (Err(e), Ok(())) => panic!("Packet has status {:?}, expected `Ok(())`", e),
    (Ok(()), Err(_)) => panic!("Packet has status `Ok(())`, expected {:?}", status),
    (Err(a), Err(b)) => {
      if a == b {
        assert!(true);
      } else {
        panic!("Packet has status {:?}, expected {:?}", a, b);
      }
    }
  };
  assert_eq!(packet.total_len(), total);
  assert_eq!(packet.get_keylen(), key);
  assert_eq!(packet.get_extralen(), extra);
  assert_eq!(packet.get_bodylen(), body);
  let mut e = unsafe{ Encoder::with_capacity(4096) };
  packet.encode(&mut e);
  assert_eq!(e.len(), 24);
  assert_eq!(e.as_slice(), &msg[0..24]);
}
fn test_res_header_fail(msg: &[u8], fault: Fault) {
  match ResHeader::parse(msg) {
    ParseResult::Ok(_) => panic!("Parsing should not succeed ... expected error code {:?}", fault),
    ParseResult::Err(e) => if e != fault {
        panic!("Parsing failed with {:?} ... expected {:?}", e, fault);
      } else {
        assert!(true);
      }
  };
}



/*
 *
 *
 * Assertions about Request
 *
 *
 *
 */
fn test_request(msg: &[u8], o: u32, c: u64, code: OpCode, vb: u16, k: usize, e: usize, b: usize, t: usize, ex: Option<&[u8]>, ke: Option<&[u8]>, bo: Option<&[u8]>) {
  let packet = match Request::parse(msg) {
    ParseResult::Ok(x) => x,
    ParseResult::Err(e) => panic!("ResHeader::parse failed with {:?}",e)
  };
  assert_eq!(packet.get_opaque(), o);
  assert_eq!(packet.get_cas(), c);
  assert_eq!(packet.get_opcode(), code);
  assert_eq!(packet.get_vbucket_id(), vb);
  assert_eq!(packet.get_keylen(), k);
  assert_eq!(packet.get_bodylen(), b);
  assert_eq!(packet.get_extralen(), e);
  assert_eq!(packet.total_len(), t);
  assert_eq!(packet.get_extra(), ex);
  assert_eq!(packet.get_key(), ke);
  assert_eq!(packet.get_body(), bo);
  let mut e = unsafe{ Encoder::with_capacity(4096) };
  packet.encode(&mut e);
  assert_eq!(e.len(), t);
  assert_eq!(e.len(), packet.total_len());
  assert_eq!(e.as_slice(), msg);
}
fn test_request_fail(msg: &[u8], fault: Fault) {
  match Request::parse(msg) {
    ParseResult::Ok(_) => panic!("Parsing should not succeed ... expected error code {:?}", fault),
    ParseResult::Err(e) => if e != fault {
        panic!("Parsing failed with {:?} ... expected {:?}", e, fault);
      } else {
        assert!(true);
      }
  };
}






/*
 *
 *
 * Assertions about Response
 *
 *
 *
 */
fn test_response(msg: &[u8], opaque: u32, cas: u64, code: OpCode, status: StatusField, key: usize, extra: usize, body: usize, total: usize, ex: Option<&[u8]>, ke: Option<&[u8]>, bo: Option<&[u8]>) {
  let packet = match Response::parse(msg) {
    ParseResult::Ok(x) => x,
    ParseResult::Err(e) => panic!("ResHeader::parse failed with {:?}",e)
  };
  assert_eq!(packet.get_opaque(), opaque);
  assert_eq!(packet.get_cas(), cas);
  assert_eq!(packet.get_opcode(), code);
  match (packet.check_status(), status.check_status()) {
    (Ok(()), Ok(())) => { },
    (Err(e), Ok(())) => panic!("Packet has status {:?}, expected `Ok(())`", e),
    (Ok(()), Err(_)) => panic!("Packet has status `Ok(())`, expected {:?}", status),
    (Err(a), Err(b)) => {
      if a == b {
        assert!(true);
      } else {
        panic!("Packet has status {:?}, expected {:?}", a, b);
      }
    }
  };
  assert_eq!(packet.get_keylen(), key);
  assert_eq!(packet.get_bodylen(), body);
  assert_eq!(packet.get_extralen(), extra);
  assert_eq!(packet.total_len(), total);
  assert_eq!(packet.get_extra(), ex);
  assert_eq!(packet.get_key(), ke);
  assert_eq!(packet.get_body(), bo);
  let mut e = unsafe{ Encoder::with_capacity(4096) };
  packet.encode(&mut e);
  assert_eq!(e.len(), msg.len());
  assert_eq!(e.len(), packet.total_len());
  assert_eq!(e.len(), total);
  assert_eq!(e.as_slice(), msg);
}
fn test_response_fail(msg: &[u8], fault: Fault) {
  match Response::parse(msg) {
    ParseResult::Ok(_) => panic!("Parsing should not succeed ... expected error code {:?}", fault),
    ParseResult::Err(e) => if e != fault {
        panic!("Parsing failed with {:?} ... expected {:?}", e, fault);
      } else {
        assert!(true);
      }
  };
}



/*
 *
 *
 * Sample Error Message from https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#commands   
 *
 *
 *
 */
#[test]
fn error_message_response() {
  
  
  let err_msg: Vec<u8> = vec![
    0x81, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x4E, 0x6F, 0x74, 0x20,
    0x66, 0x6F, 0x75, 0x6E,
    0x64
  ];

  test_res_header(&err_msg, 0, 0, OpCode::Get, StatusField::KeyNotFound, 0, 0, 9, 33);
  test_req_header_fail(&err_msg, Fault::BadMagic);

  test_response(&err_msg, 0, 0, OpCode::Get, StatusField::KeyNotFound, 0, 0, 9, 33, None, None, Some(b"Not found"));
  test_request_fail(&err_msg, Fault::BadMagic);
}



/*
 *
 *
 * Sample Message from https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#get-get-quietly-get-key-get-key-quietly
 *
 *
 *
 */
#[test]
fn get_request() {
  
  
  let msg: Vec<u8> = vec![
    0x80, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x48, 0x65, 0x6C, 0x6C,
    0x6F
  ];
  
  test_res_header_fail(&msg, Fault::BadMagic);
  test_req_header(&msg, 0, 0, OpCode::Get, 0, 5, 0, 0, 29);

  test_response_fail(&msg, Fault::BadMagic);
  test_request(&msg, 0, 0, OpCode::Get, 0, 5, 0, 0, 29, None, Some(b"Hello"), None);
}



/*
 *
 *
 * Sample Message from https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#get-get-quietly-get-key-get-key-quietly
 *
 *
 *
 */
#[test]
fn get_response() {
  
  
  let msg: Vec<u8> = vec![
    0x81, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0xDE, 0xAD, 0xBE, 0xEF,
    0x57, 0x6F, 0x72, 0x6C,
    0x64
  ];
  
  test_res_header(&msg, 0, 1, OpCode::Get, StatusField::NoError, 0, 4, 5, 33);
  test_req_header_fail(&msg, Fault::BadMagic);

  test_response(&msg, 0, 1, OpCode::Get, StatusField::NoError, 0, 4, 5, 33, Some(b"\xDE\xAD\xBE\xEF"), None, Some(b"World"));
  test_request_fail(&msg, Fault::BadMagic);
}



/*
 *
 *
 * Sample Message from https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#get-get-quietly-get-key-get-key-quietly
 *
 *
 *
 */
#[test]
fn get_response_with_k() {
  
  
  let msg: Vec<u8> = vec![
    0x81, 0x00, 0x00, 0x05,
    0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0E,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0xDE, 0xAD, 0xBE, 0xEF,
    0x48, 0x65, 0x6C, 0x6C,
    0x6F, 0x57, 0x6F, 0x72,
    0x6C, 0x64
  ];
  //sanity check
  assert_eq!(msg.len(), 38);

  test_res_header(&msg, 0, 1, OpCode::Get, StatusField::NoError, 5, 4, 5, 38);
  test_req_header_fail(&msg, Fault::BadMagic);

  test_response(&msg, 0, 1, OpCode::Get, StatusField::NoError, 5, 4, 5, 38, Some(b"\xDE\xAD\xBE\xEF"), Some(b"Hello"), Some(b"World"));
  test_request_fail(&msg, Fault::BadMagic);
}



/*
 *
 *
 * Sample Message from https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#set-add-replace
 *
 *
 *
 */
#[test]
fn add_request() {
  
  
  let msg: Vec<u8> = vec![
    0x80, 0x02, 0x00, 0x05,
    0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x12,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
    0x00, 0x00, 0x0E, 0x10,
    0x48, 0x65, 0x6C, 0x6C,
    0x6F, 0x57, 0x6F, 0x72,
    0x6C, 0x64
  ];
  assert_eq!(msg.len(), 42);

  test_res_header_fail(&msg, Fault::BadMagic);
  test_req_header(&msg, 0, 0, OpCode::Add, 0, 5, 8, 5, 42,);

  test_response_fail(&msg, Fault::BadMagic);
  test_request(&msg, 0, 0, OpCode::Add , 0, 5, 8, 5, 42, Some(b"\xDE\xAD\xBE\xEF\x00\x00\x0E\x10"), Some(b"Hello"), Some(b"World"));
}



/*
 *
 *
 * Sample Message from https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#set-add-replace
 *
 *
 *
 */
#[test]
fn add_response() {
  
  
  let msg: Vec<u8> = vec![
    0x81, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
  ];
  //sanity check
  assert_eq!(msg.len(), 24);

  test_res_header(&msg, 0, 1, OpCode::Add, StatusField::NoError, 0, 0, 0, 24);
  test_req_header_fail(&msg, Fault::BadMagic);

  test_response(&msg, 0, 1, OpCode::Add, StatusField::NoError, 0, 0, 0, 24, None, None, None);
  test_request_fail(&msg, Fault::BadMagic);
}

