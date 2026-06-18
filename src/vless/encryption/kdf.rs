//! BLAKE3 derive-key with an arbitrary byte context, matching Go's string bytes.

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[derive(Clone)]
struct Output {
    cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let words = compress(
            &self.cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        );
        words[..8].try_into().unwrap()
    }

    fn root_hash(&self) -> [u8; 32] {
        let words = compress(&self.cv, &self.block, 0, self.block_len, self.flags | ROOT);
        words_to_bytes(&words[..8])
    }
}

pub fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    let context_key = hash_mode(context, IV, DERIVE_KEY_CONTEXT);
    let key_words = bytes_to_words_8(&context_key);
    hash_mode(material, key_words, DERIVE_KEY_MATERIAL)
}

fn hash_mode(input: &[u8], key: [u32; 8], flags: u32) -> [u8; 32] {
    let chunks = input.chunks(CHUNK_LEN).count().max(1);
    let mut stack = Vec::<[u32; 8]>::new();
    let mut final_output = None;

    for chunk_index in 0..chunks {
        let start = chunk_index * CHUNK_LEN;
        let end = input.len().min(start + CHUNK_LEN);
        let chunk = if start < input.len() {
            &input[start..end]
        } else {
            &[]
        };
        let output = chunk_output(chunk, chunk_index as u64, key, flags);
        if chunk_index + 1 == chunks {
            final_output = Some(output);
            break;
        }
        let mut cv = output.chaining_value();
        let mut total_chunks = chunk_index + 1;
        while total_chunks & 1 == 0 {
            cv = parent_output(stack.pop().unwrap(), cv, key, flags).chaining_value();
            total_chunks >>= 1;
        }
        stack.push(cv);
    }

    let mut output = final_output.unwrap();
    while let Some(left) = stack.pop() {
        output = parent_output(left, output.chaining_value(), key, flags);
    }
    output.root_hash()
}

fn chunk_output(chunk: &[u8], counter: u64, key: [u32; 8], flags: u32) -> Output {
    let blocks = chunk.chunks(BLOCK_LEN).count().max(1);
    let mut cv = key;
    for block_index in 0..blocks {
        let start = block_index * BLOCK_LEN;
        let end = chunk.len().min(start + BLOCK_LEN);
        let block_bytes = if start < chunk.len() {
            &chunk[start..end]
        } else {
            &[]
        };
        let mut block = [0u8; BLOCK_LEN];
        block[..block_bytes.len()].copy_from_slice(block_bytes);
        let block_words = bytes_to_words_16(&block);
        let mut block_flags = flags;
        if block_index == 0 {
            block_flags |= CHUNK_START;
        }
        if block_index + 1 == blocks {
            block_flags |= CHUNK_END;
            return Output {
                cv,
                block: block_words,
                counter,
                block_len: block_bytes.len() as u32,
                flags: block_flags,
            };
        }
        cv = compress(&cv, &block_words, counter, BLOCK_LEN as u32, block_flags)[..8]
            .try_into()
            .unwrap();
    }
    unreachable!()
}

fn parent_output(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    Output {
        cv: key,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;
    for schedule in SCHEDULE {
        round(&mut state, block, &schedule);
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn round(state: &mut [u32; 16], msg: &[u32; 16], s: &[usize; 16]) {
    g(state, 0, 4, 8, 12, msg[s[0]], msg[s[1]]);
    g(state, 1, 5, 9, 13, msg[s[2]], msg[s[3]]);
    g(state, 2, 6, 10, 14, msg[s[4]], msg[s[5]]);
    g(state, 3, 7, 11, 15, msg[s[6]], msg[s[7]]);
    g(state, 0, 5, 10, 15, msg[s[8]], msg[s[9]]);
    g(state, 1, 6, 11, 12, msg[s[10]], msg[s[11]]);
    g(state, 2, 7, 8, 13, msg[s[12]], msg[s[13]]);
    g(state, 3, 4, 9, 14, msg[s[14]], msg[s[15]]);
}

fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn bytes_to_words_8(bytes: &[u8; 32]) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn bytes_to_words_16(bytes: &[u8; 64]) -> [u32; 16] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn words_to_bytes(words: &[u32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (word, bytes) in words.iter().zip(out.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_blake3_for_utf8_contexts() {
        for material in [&b""[..], &b"material"[..], &[7u8; 2049][..]] {
            assert_eq!(
                derive_key(b"VLESS test context", material),
                blake3::derive_key("VLESS test context", material)
            );
        }
    }

    #[test]
    fn matches_go_for_binary_context() {
        let context = [0, 0xff, 0x80, b'X', 0, 1, 2, 3];
        let expected = [
            0x92, 0xe8, 0x38, 0x87, 0x05, 0xbd, 0xdc, 0xee, 0x98, 0x04, 0xd6, 0xd2, 0xd2, 0x94,
            0x83, 0xfd, 0xa3, 0x6c, 0xfe, 0xe9, 0xe9, 0xf5, 0x92, 0x61, 0xe7, 0x12, 0x02, 0x27,
            0x5f, 0x31, 0x44, 0x32,
        ];
        assert_eq!(derive_key(&context, b"key material"), expected);
    }
}
