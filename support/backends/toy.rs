// Deliberately insecure teaching transforms. The envelope supplies integrity only.
fn transform(key: &[u8], data: &[u8], inverse: bool) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 {
        return Err(invalid());
    }
    let mut output = Zeroizing::new(data.to_vec());
    let mut state = u64::from_le_bytes(key[..8].try_into().map_err(|_| invalid())?) | 1;
    let mut permutation: [u8; 256] = std::array::from_fn(|i| i as u8);
    for i in (1..256).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        permutation.swap(i, (state % (i as u64 + 1)) as usize);
    }
    let mut inverse_permutation = [0u8; 256];
    for (i, &value) in permutation.iter().enumerate() {
        inverse_permutation[value as usize] = i as u8;
    }
    let multiplier = key[0] | 1;
    let reciprocal = (1..=255u8)
        .find(|&i| i.wrapping_mul(multiplier) == 1)
        .ok_or_else(invalid)?;
    for (i, byte) in output.iter_mut().enumerate() {
        let k = key[i % key.len()];
        *byte = match TOY {
            "repeating-xor" => *byte ^ k,
            "repeating-add" => {
                if inverse {
                    byte.wrapping_sub(k)
                } else {
                    byte.wrapping_add(k)
                }
            }
            "beaufort-byte" => k.wrapping_sub(*byte),
            "affine-byte" => {
                if inverse {
                    byte.wrapping_sub(key[1]).wrapping_mul(reciprocal)
                } else {
                    byte.wrapping_mul(multiplier).wrapping_add(key[1])
                }
            }
            "rotate-byte" => {
                if inverse {
                    byte.rotate_right(u32::from(k & 7))
                } else {
                    byte.rotate_left(u32::from(k & 7))
                }
            }
            "xor-rotate" => {
                if inverse {
                    byte.rotate_right(u32::from(k & 7)) ^ k
                } else {
                    (*byte ^ k).rotate_left(u32::from(k & 7))
                }
            }
            "substitution" => {
                if inverse {
                    inverse_permutation[*byte as usize]
                } else {
                    permutation[*byte as usize]
                }
            }
            "xorshift64" => {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte ^ (state >> 56) as u8
            }
            "lcg64" => {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte ^ (state >> 56) as u8
            }
            _ => return Err(invalid()),
        };
    }
    Ok(output)
}
fn encrypt(key: &[u8], _: &[u8], _: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    transform(key, data, false)
}
fn decrypt(key: &[u8], _: &[u8], _: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    transform(key, data, true)
}
