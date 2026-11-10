//! config.rs: the house sponsors, one bit of Config.house_sponsors per place on the sponsor list.
//! Config::without_bit (the re-pack disallow does as the list closes up behind a removed sponsor)
//! over every u32 and every index, and Config::disallow and is_house_sponsor on a whole list.

use {
    crate::{code, escrow_error, zeroed},
    anchor_lang::prelude::Pubkey,
    prize_escrow::{AllowList, Config, EscrowError},
};

fn key(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

fn bit(bits: u32, index: u32) -> bool {
    (bits >> index) & 1 == 1
}

/// For every u32 of bits and every index (all of usize below 64, past the 32 bits too):
/// without_bit keeps every bit below the index, moves every bit above it down one place, and
/// clears the top bit; an index past 31 leaves the bits as they are.
#[kani::proof]
#[kani::unwind(34)]
fn without_bit_closes_up_the_bits_behind_the_index() {
    let bits: u32 = kani::any();
    let index: usize = kani::any();
    kani::assume(index < 64);
    let got = Config::without_bit(bits, index);
    if index >= 32 {
        assert_eq!(got, bits);
    } else {
        let index = index as u32;
        for j in 0..32u32 {
            let want = if j < index {
                bit(bits, j)
            } else if j < 31 {
                bit(bits, j + 1)
            } else {
                false
            };
            assert_eq!(bit(got, j), want);
        }
    }
    kani::cover!(
        index == 0 && bits & 1 == 1,
        "the first sponsor removed, marked"
    );
    kani::cover!(
        index == 31 && bit(bits, 31),
        "the last place removed, marked"
    );
    kani::cover!(index >= 32, "an index past the bits");
}

/// On a list of LEN sponsors with any marks (bits above the list clear, the invariant
/// set_allowed keeps), removing the one at PICK (PICK == LEN: a key not listed, NotListed, nothing
/// changes) leaves every other sponsor listed in order with its own mark, the removed one unmarked
/// and unlisted, and no bit at or above the shorter list set. Every key and the place removed are
/// concrete (one harness per place) and the marks symbolic: a symbolic place made CBMC compare
/// every key with every other, past the Docker VM's memory.
fn removing_a_sponsor_keeps_every_other_mark<const LEN: usize, const PICK: usize>() {
    let mut config: Config = zeroed();
    let keys: [Pubkey; LEN] = core::array::from_fn(|i| key(10 + i as u8));
    config.sponsors = keys.to_vec();
    let marks: u32 = kani::any();
    config.house_sponsors = marks & ((1u32 << LEN) - 1);
    let before = config.house_sponsors;

    let removed = if PICK < LEN { keys[PICK] } else { key(99) };
    let got = code(&config.disallow(AllowList::Sponsor, removed));

    if PICK == LEN {
        assert_eq!(got, escrow_error(EscrowError::NotListed));
        assert_eq!(config.house_sponsors, before);
        assert_eq!(config.sponsors.len(), LEN);
    } else {
        assert_eq!(got, None);
        assert_eq!(config.sponsors.len(), LEN - 1);
        assert!(!config.is_house_sponsor(&removed));
        let mut place = 0;
        for (i, k) in keys.iter().enumerate() {
            if i == PICK {
                continue;
            }
            assert!(config.sponsors[place] == *k);
            assert_eq!(config.is_house_sponsor(k), bit(before, i as u32));
            place += 1;
        }
        assert_eq!(config.house_sponsors >> (LEN - 1), 0);
    }
    kani::cover!(
        PICK < LEN && bit(before, PICK as u32),
        "a house sponsor removed"
    );
    kani::cover!(
        PICK + 1 < LEN && bit(before, LEN as u32 - 1),
        "a marked sponsor after the removed one moves down"
    );
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(34)]
fn removing_the_first_of_3_sponsors_keeps_every_other_mark() {
    removing_a_sponsor_keeps_every_other_mark::<3, 0>();
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(34)]
fn removing_the_middle_of_3_sponsors_keeps_every_other_mark() {
    removing_a_sponsor_keeps_every_other_mark::<3, 1>();
}
