// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use bitfield::bitfield;

use super::SframeHeader;

bitfield! {
    /// Modeled after [sframe draft 04 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-04#name-sframe-header)
    /// ```txt
    ///   0 1 2 3 4 5 6 7
    ///  +-+-+-+-+-+-+-+-+
    ///  |X|  K  |Y|  C  |
    ///  +-+-+-+-+-+-+-+-+
    ///
    /// X: Extended Key ID Flag
    /// K: Key ID Value (KID) or Length (KLEN)
    /// Y: Extended Counter Flag
    /// C: Counter Value (CTR) or Length (CLEN)
    pub struct ConfigByte(MSB0 [u8]);
    impl Debug;
    u8;
    #[inline]
    pub extended_key_flag, set_extended_key_flag: 0;
    #[inline]
    pub key_or_klen, set_key_or_klen: 3 , 1;
    #[inline]
    pub extended_ctr_flag, set_extended_ctr_flag: 4;
    #[inline]
    pub ctr_or_clen, set_ctr_or_clen: 7 , 5;
}

impl<T: AsRef<[u8]>> ConfigByte<T> {
    pub fn header_len(&self) -> usize {
        let mut len = SframeHeader::STATIC_HEADER_LENGTH;

        if self.extended_key_flag() {
            len += (self.key_or_klen() + SframeHeader::LEN_OFFSET) as usize;
        }

        if self.extended_ctr_flag() {
            len += (self.ctr_or_clen() + SframeHeader::LEN_OFFSET) as usize;
        }

        len
    }
}

impl<'a> From<&'a u8> for ConfigByte<&'a [u8]> {
    fn from(value: &'a u8) -> Self {
        // we have to pass a slice here, as bitfield doesn't allow using MSB0 otherwise
        ConfigByte(std::slice::from_ref(value))
    }
}

impl<'a> From<&'a mut u8> for ConfigByte<&'a mut [u8]> {
    fn from(value: &'a mut u8) -> Self {
        // we have to pass a slice here, as bitfield doesn't allow using MSB0 otherwise
        ConfigByte(std::slice::from_mut(value))
    }
}
