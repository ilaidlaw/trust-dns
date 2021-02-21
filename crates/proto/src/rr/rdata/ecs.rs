/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ipnet::IpNet;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use std::convert::From;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use crate::error::*;
//use crate::serialize::binary::{BinEncodable, BinEncoder};
use crate::serialize::binary::*;

/// ```text
///!This protocol uses an EDNS0 [RFC6891] option to include client
///!   address information in DNS messages.  The option is structured as
///!   follows:
///!
///!                +0 (MSB)                            +1 (LSB)
///!      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///!   0: |                          OPTION-CODE                          |
///!      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///!   2: |                         OPTION-LENGTH                         |
///!      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///!   4: |                            FAMILY                             |
///!      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///!   6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
///!      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///!   8: |                           ADDRESS...                          /
///!      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///!
///!   o  (Defined in [RFC6891]) OPTION-CODE, 2 octets, for ECS is 8 (0x00
///!      0x08).
///!
///!   o  (Defined in [RFC6891]) OPTION-LENGTH, 2 octets, contains the
///!      length of the payload (everything after OPTION-LENGTH) in octets.
///!
///!   o  FAMILY, 2 octets, indicates the family of the address contained in
///!      the option, using address family codes as assigned by IANA in
///!      Address Family Numbers [Address_Family_Numbers].
///!
///!   The format of the address part depends on the value of FAMILY.  This
///!   document only defines the format for FAMILY 1 (IPv4) and FAMILY 2
///!   (IPv6), which are as follows:
///!
///!   o  SOURCE PREFIX-LENGTH, an unsigned octet representing the leftmost
///!      number of significant bits of ADDRESS to be used for the lookup.
///!      In responses, it mirrors the same value as in the queries.
///!   o  SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
///!      number of significant bits of ADDRESS that the response covers.
///!      In queries, it MUST be set to 0.
///!
///!   o  ADDRESS, variable number of octets, contains either an IPv4 or
///!      IPv6 address, depending on FAMILY, which MUST be truncated to the
///!      number of bits indicated by the SOURCE PREFIX-LENGTH field,
///!      padding with 0 bits to pad to the end of the last octet needed.
///!
///!   o  A server receiving an ECS option that uses either too few or too
///!      many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
///!      SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
///!      as a signal to the software developer making the request to fix
///!      their implementation.
///!
///!   All fields are in network byte order ("big-endian", per [RFC1700],
///!   Data Notation).
///```

#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Hash)]
pub struct EdnsClientSubnet {
    subnet: IpNet,
    scope_prefix_len: u8,
}

struct Inner {
    subnet: IpNet,
    scope_prefix_len: u8,
}

impl EdnsClientSubnet {
    pub fn new(subnet: IpNet) -> Self {
        Self {
            subnet,
            scope_prefix_len: 0,
        }
    }

    pub fn len(&self) -> u16 {
        //let addr_len = match self.subnet {
        //    IpNet::V4(addr) => ((addr.prefix_len() + 7) / 8) as usize,
        //    IpNet::V6(addr) => ((addr.prefix_len() + 7) / 8) as usize,
        //};
        let addr_len = ((self.subnet.prefix_len() + 7) / 8) as usize;

        // Family + Source Prefix-Len + Scope Prefix-Len + Address
        //2 + 1 + 1 + addr_len as u16
        2 + 1 + 1 + addr_len as u16
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

impl<'a> From<&'a [u8]> for EdnsClientSubnet {
    fn from(values: &'a [u8]) -> Self {
        println!("values: {:?}", values);

        let addr: IpNet = "1.2.3.4/16".parse().unwrap();
        Self {
            subnet: addr,
            scope_prefix_len: 0,
        }
    }
}

fn decode(values: &[u8]) -> Option<Inner> {
    let ip_type = values.get(..=1)?;
    let prefix_len = values.get(2)?;
    let scope_len = values.get(3)?;
    let addr = values.get(4..)?;

    if ip_type[1] == 1 {
        let mut subnet = vec![0; 4];
        subnet.splice(..addr.len(), addr.iter().cloned());
        let ipaddr = Ipv4Addr::new(subnet[0], subnet[1], subnet[2], subnet[3]);
        let ipnet = IpNet::V4(Ipv4Net::new(ipaddr, *prefix_len).ok()?);
    } else if ip_type[1] == 2 {
        let mut subnet = vec![0; 16];
        subnet.splice(..addr.len(), addr.iter().cloned());
        let ipaddr = Ipv6Addr::new(
            ((subnet[0] as u16) << 8) | subnet[1] as u16,
            ((subnet[2] as u16) << 8) | subnet[3] as u16,
            ((subnet[4] as u16) << 8) | subnet[5] as u16,
            ((subnet[6] as u16) << 8) | subnet[7] as u16,
            ((subnet[8] as u16) << 8) | subnet[9] as u16,
            ((subnet[10] as u16) << 8) | subnet[11] as u16,
            ((subnet[12] as u16) << 8) | subnet[13] as u16,
            ((subnet[14] as u16) << 8) | subnet[15] as u16,
        );
        let ipnet = IpNet::V6(Ipv6Net::new(ipaddr, *prefix_len).ok()?);
    } else {
        return None;
    }

    //subnet.splice(..addr.len(), addr.iter().cloned());
    //let ipnet: Ipv6Addr = subnet.into();

    dbg!(addr);
    //dbg!(subnet);

    None
}

impl<'a> From<&'a EdnsClientSubnet> for Vec<u8> {
    fn from(value: &'a EdnsClientSubnet) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        let _ = value.emit(&mut encoder);

        bytes
    }
}

const SOURCE_IP_TYPE_IPV4: [u8; 2] = [0, 0x01];
const SOURCE_IP_TYPE_IPV6: [u8; 2] = [0, 0x02];

impl BinEncodable for EdnsClientSubnet {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        match self.subnet {
            IpNet::V4(addr) => {
                let sig_len = ((addr.prefix_len() + 7) / 8) as usize;
                encoder.emit_vec(&SOURCE_IP_TYPE_IPV4)?;
                encoder.emit_u8(addr.prefix_len())?;
                encoder.emit_u8(self.scope_prefix_len)?;
                let net = addr.trunc().addr().octets();
                encoder.emit_vec(&net[..sig_len])?;
            }
            IpNet::V6(addr) => {
                let sig_len = ((addr.prefix_len() + 7) / 8) as usize;
                encoder.emit_vec(&SOURCE_IP_TYPE_IPV6)?;
                encoder.emit_u8(addr.prefix_len())?;
                encoder.emit_u8(self.scope_prefix_len)?;
                let net = addr.trunc().addr().octets();
                encoder.emit_vec(&net[..sig_len])?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::op::Edns;

    use super::*;
    #[test]
    fn test_ecs_ipv4() {
        let addr: IpNet = "1.2.3.4/16".parse().unwrap();
        let ecs = EdnsClientSubnet::new(addr);
        dbg!(addr);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(ecs.emit(&mut encoder).is_ok());

        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let subnet: EdnsClientSubnet = bytes[..].into();
        dbg!(subnet);
    }

    #[test]
    fn test_ecs_ipv6() {
        let addr: IpNet = "2001:0db8:85a3:0000:0000:8a2e:0370:7334/56"
            .parse()
            .unwrap();
        let ecs = EdnsClientSubnet::new(addr);
        dbg!(addr);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(ecs.emit(&mut encoder).is_ok());

        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);
    }

    #[test]
    fn test_into_vec() {
        let addr: IpNet = "2001:0db8:85a3:0000:0000:8a2e:0370:7334/56"
            .parse()
            .unwrap();
        let ecs = EdnsClientSubnet::new(addr);

        let vec: Vec<u8> = (&ecs).into();
        dbg!(vec);
    }

    #[test]
    fn from_vec() {
        let subnet: Vec<u8> = vec![0, 2, 56, 0, 32, 1, 13, 184, 133, 163, 0];

        let ecs: EdnsClientSubnet = subnet.as_slice().into();
    }

    #[test]
    fn test_decode() {
        let subnet: Vec<u8> = vec![0, 2, 56, 0, 32, 1, 13, 184, 133, 163, 0];

        decode(subnet.as_slice());
    }
}
