//! Perceptual hashing of captured screenshots.
//!
//! The same login panel, router admin page or default install screen appears
//! across thousands of unrelated hosts, and finding all of them is a genuine
//! pivot. Comparing PNG bytes cannot do it: two captures of the same page
//! differ in timestamps, antialiasing and compression, so their bytes — and
//! any cryptographic hash of them — are unrelated.
//!
//! A *perceptual* hash compares what the image looks like. This implements
//! dHash (difference hash): reduce to a 9x8 grayscale grid and record, for
//! each row, whether each pixel is brighter than the one to its right. The
//! result is 64 bits describing gradients rather than absolute values, which
//! makes it stable under rescaling, compression and brightness shifts while
//! staying sensitive to layout. Similarity is Hamming distance, so "pages that
//! look like this one" is a cheap integer comparison.
//!
//! dHash is chosen over a CLIP-style embedding deliberately: for near-duplicate
//! template matching, perceptual hashing is enough (VisualPhishNet,
//! arXiv:1909.00300; PhishSnap, arXiv:2512.02243), and it needs no model, no
//! GPU and no inference. A learned embedding is the better tool for *semantic*
//! similarity between pages that merely serve the same purpose, and belongs on
//! top of this rather than instead of it.

use anyhow::{Context, Result};

/// Width of the sampling grid. One more than the height, because each row
/// yields `WIDTH - 1` comparisons.
const GRID_W: usize = 9;
/// Height of the sampling grid.
const GRID_H: usize = 8;

/// Minimum dynamic range the reduced grid must span before a hash is
/// meaningful, out of 255.
///
/// dHash encodes *gradients*, so a uniform image produces all-zero bits — and
/// since Hamming distance to that hash is just the popcount of the other, any
/// sparse hash lands close to it. A blank or near-blank page therefore has no
/// perceptual identity and must be refused rather than hashed: emitting a hash
/// would make every flat page a near-duplicate of every other.
const MIN_GRID_RANGE: u32 = 24;

/// Hamming distance at or below which two screenshots are "the same page".
///
/// Chosen on the conservative side: 64-bit dHash distances for genuinely
/// different pages are typically well above 20, while re-captures of one page
/// land in the low single digits.
pub const SAME_PAGE_DISTANCE: u32 = 10;

/// Decode a PNG into 8-bit grayscale, returning `(width, height, pixels)`.
///
/// Screenshots come from headless Chrome, so PNG is the only format that needs
/// handling. Alpha is composited over white, since a transparent region of a
/// web page renders white in practice and treating it as black would invert
/// the gradients the hash is built from.
fn decode_grayscale(png_bytes: &[u8]) -> Result<(usize, usize, Vec<u8>)> {
    let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = decoder.read_info().context("not a readable PNG")?;
    let mut buf = vec![0u8; reader.output_buffer_size().unwrap_or(0)];
    let info = reader.next_frame(&mut buf).context("decoding PNG frame")?;
    let (w, h) = (info.width as usize, info.height as usize);
    if w == 0 || h == 0 {
        anyhow::bail!("PNG has zero area");
    }

    let channels = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        other => anyhow::bail!("unsupported PNG colour type {other:?}"),
    };
    // 16-bit samples arrive big-endian; take the high byte of each.
    let stride = if info.bit_depth == png::BitDepth::Sixteen {
        2
    } else {
        1
    };

    let mut gray = Vec::with_capacity(w * h);
    for i in 0..w * h {
        let at = i * channels * stride;
        let sample = |c: usize| -> u32 { buf.get(at + c * stride).copied().unwrap_or(0) as u32 };
        let (r, g, b, a) = match channels {
            1 => (sample(0), sample(0), sample(0), 255),
            2 => (sample(0), sample(0), sample(0), sample(1)),
            3 => (sample(0), sample(1), sample(2), 255),
            _ => (sample(0), sample(1), sample(2), sample(3)),
        };
        // Rec. 601 luma, then composite over white.
        let luma = (r * 299 + g * 587 + b * 114) / 1000;
        let over_white = (luma * a + 255 * (255 - a)) / 255;
        gray.push(over_white.min(255) as u8);
    }
    Ok((w, h, gray))
}

/// Average an image down to `GRID_W` x `GRID_H` by box filter.
///
/// Averaging rather than sampling matters: picking single pixels from a page
/// of text would hash the position of individual glyphs, which changes between
/// captures, instead of the layout.
fn downscale(w: usize, h: usize, pixels: &[u8]) -> [[u32; GRID_W]; GRID_H] {
    let mut grid = [[0u32; GRID_W]; GRID_H];
    for (gy, row) in grid.iter_mut().enumerate() {
        let y0 = gy * h / GRID_H;
        let y1 = (((gy + 1) * h) / GRID_H).max(y0 + 1).min(h);
        for (gx, cell) in row.iter_mut().enumerate() {
            let x0 = gx * w / GRID_W;
            let x1 = (((gx + 1) * w) / GRID_W).max(x0 + 1).min(w);
            let mut sum = 0u64;
            let mut n = 0u64;
            for y in y0..y1 {
                for x in x0..x1 {
                    sum += u64::from(pixels[y * w + x]);
                    n += 1;
                }
            }
            *cell = sum.checked_div(n).unwrap_or(0) as u32;
        }
    }
    grid
}

/// Perceptual hash of a PNG screenshot.
///
/// The 64 bits are row-major: bit `y * 8 + x` is set when the pixel at
/// `(x, y)` of the reduced grid is brighter than the one to its right.
pub fn screenshot_hash(png_bytes: &[u8]) -> Result<u64> {
    let (w, h, pixels) = decode_grayscale(png_bytes)?;
    let grid = downscale(w, h, &pixels);

    // Refuse an image with nothing to fingerprint. See MIN_GRID_RANGE.
    let flat = grid.iter().flatten().copied();
    let (lo, hi) = flat.fold((u32::MAX, 0u32), |(lo, hi), v| (lo.min(v), hi.max(v)));
    if hi.saturating_sub(lo) < MIN_GRID_RANGE {
        anyhow::bail!(
            "screenshot is too uniform to fingerprint (brightness range {} of {MIN_GRID_RANGE} needed)",
            hi.saturating_sub(lo)
        );
    }

    let mut hash = 0u64;
    let mut bit = 0;
    for row in grid.iter() {
        for x in 0..GRID_W - 1 {
            if row[x] > row[x + 1] {
                hash |= 1 << bit;
            }
            bit += 1;
        }
    }
    Ok(hash)
}

/// How many bits two hashes differ in: 0 is identical, 64 is opposite.
pub fn distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Whether two screenshots are near-duplicates of the same page.
pub fn same_page(a: u64, b: u64) -> bool {
    distance(a, b) <= SAME_PAGE_DISTANCE
}

/// Group hashes into near-duplicate sets.
///
/// Greedy single-link clustering around the first unassigned member, which is
/// enough for "show me the template groups" and keeps the output stable: the
/// same input always produces the same groups, largest first.
pub fn group<T: Clone + Ord>(items: &[(T, u64)]) -> Vec<Vec<T>> {
    let mut remaining: Vec<(T, u64)> = items.to_vec();
    remaining.sort();
    let mut groups: Vec<Vec<T>> = Vec::new();
    while let Some((seed_label, seed_hash)) = remaining.first().cloned() {
        let mut members = vec![seed_label];
        remaining.remove(0);
        remaining.retain(|(label, hash)| {
            if same_page(seed_hash, *hash) {
                members.push(label.clone());
                false
            } else {
                true
            }
        });
        members.sort();
        groups.push(members);
    }
    groups.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode an RGBA image as PNG, so tests exercise the real decoder.
    fn png_rgba(w: u32, h: u32, pixels: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut out, w, h);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(pixels).unwrap();
        }
        out
    }

    /// A page-like image: a dark bar across the top, light body, and a box
    /// wherever `offset` puts it — a crude "login panel".
    fn page(w: u32, h: u32, offset: u32, noise: u8) -> Vec<u8> {
        let mut px = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let header = y < h / 8;
                let box_x = x > w / 3 + offset && x < 2 * w / 3 + offset;
                let box_y = y > h / 3 && y < 2 * h / 3;
                let v: u8 = if header {
                    30
                } else if box_x && box_y {
                    90
                } else {
                    230
                };
                let v = v.saturating_add(((x + y) as u8 % 3) * noise);
                px.extend_from_slice(&[v, v, v, 255]);
            }
        }
        png_rgba(w, h, &px)
    }

    #[test]
    fn identical_images_hash_identically() {
        let a = screenshot_hash(&page(160, 120, 0, 0)).unwrap();
        let b = screenshot_hash(&page(160, 120, 0, 0)).unwrap();
        assert_eq!(a, b);
        assert_eq!(distance(a, b), 0);
        assert!(same_page(a, b));
    }

    #[test]
    fn rescaling_and_noise_barely_move_the_hash() {
        // The point of a perceptual hash: a re-capture at another size, with
        // compression noise, is still recognisably the same page.
        let base = screenshot_hash(&textured(320, 240, 0)).unwrap();
        let rescaled = screenshot_hash(&textured(160, 120, 0)).unwrap();
        let noisy = screenshot_hash(&page(320, 240, 0, 8)).unwrap();
        assert!(
            same_page(base, rescaled),
            "distance {} after halving the size",
            distance(base, rescaled)
        );
        // Noise alone must not break the match against the untextured twin.
        let plain = screenshot_hash(&page(320, 240, 0, 0)).unwrap();
        assert!(
            same_page(plain, noisy),
            "distance {} with noise",
            distance(plain, noisy)
        );
    }

    /// A page with text-like rows, which is what a real screenshot looks like.
    fn textured(w: u32, h: u32, offset: u32) -> Vec<u8> {
        let mut px = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let header = y < h / 8;
                let box_x = x > w / 3 + offset && x < 2 * w / 3 + offset;
                let box_y = y > h / 3 && y < 2 * h / 3;
                // Text-like: alternating glyph columns inside content areas.
                let glyph = (x / 3 + y / 7) % 2 == 0 && (y % 7) < 5;
                let v: u8 = if header {
                    if glyph {
                        60
                    } else {
                        20
                    }
                } else if box_x && box_y {
                    if glyph {
                        120
                    } else {
                        70
                    }
                } else if glyph {
                    200
                } else {
                    240
                };
                px.extend_from_slice(&[v, v, v, 255]);
            }
        }
        png_rgba(w, h, &px)
    }

    #[test]
    fn a_different_layout_is_a_different_hash() {
        let login = screenshot_hash(&textured(320, 240, 0)).unwrap();
        // Same palette and texture, panel moved: a different layout.
        let moved = screenshot_hash(&textured(320, 240, 90)).unwrap();
        assert!(
            !same_page(login, moved),
            "distance only {}",
            distance(login, moved)
        );
    }

    #[test]
    fn a_blank_page_is_refused_rather_than_hashed() {
        // The failure this guard exists for: dHash encodes gradients, so a
        // uniform page hashes to zero and every sparse hash sits close to it.
        // Hashing it anyway would make flat pages near-duplicates of each
        // other and of every lightly-decorated page.
        let white = png_rgba(64, 64, &[255u8; 64 * 64 * 4]);
        let err = screenshot_hash(&white).unwrap_err().to_string();
        assert!(err.contains("too uniform"), "{err}");

        let mut black = Vec::new();
        for _ in 0..64 * 64 {
            black.extend_from_slice(&[0, 0, 0, 255]);
        }
        assert!(screenshot_hash(&png_rgba(64, 64, &black)).is_err());

        // A page with real content is still hashed.
        assert!(screenshot_hash(&textured(320, 240, 0)).is_ok());
        assert!(screenshot_hash(&page(320, 240, 0, 0)).is_ok());
    }

    #[test]
    fn grayscale_and_rgb_of_the_same_image_agree() {
        let w = 64u32;
        let h = 64u32;
        let mut rgb = Vec::new();
        let mut gray = Vec::new();
        for y in 0..h {
            for x in 0..w {
                let v = ((x * 4 + y) % 256) as u8;
                rgb.extend_from_slice(&[v, v, v]);
                gray.push(v);
            }
        }
        let png_rgb = {
            let mut out = Vec::new();
            let mut e = png::Encoder::new(&mut out, w, h);
            e.set_color(png::ColorType::Rgb);
            e.set_depth(png::BitDepth::Eight);
            e.write_header().unwrap().write_image_data(&rgb).unwrap();
            out
        };
        let png_gray = {
            let mut out = Vec::new();
            let mut e = png::Encoder::new(&mut out, w, h);
            e.set_color(png::ColorType::Grayscale);
            e.set_depth(png::BitDepth::Eight);
            e.write_header().unwrap().write_image_data(&gray).unwrap();
            out
        };
        assert_eq!(
            screenshot_hash(&png_rgb).unwrap(),
            screenshot_hash(&png_gray).unwrap(),
            "a grey RGB image and its grayscale twin must hash alike"
        );
    }

    #[test]
    fn transparency_composites_over_white_not_black() {
        // A transparent region of a page renders white, so it must hash like
        // white. Treating it as black would invert the gradients the hash is
        // built from. Both images need real structure to pass the uniformity
        // guard, so each is half dark bar, half "nothing".
        let w = 64u32;
        let mut clear = Vec::new();
        let mut white = Vec::new();
        for y in 0..w {
            for x in 0..w {
                let bar = x < w / 2;
                if bar {
                    clear.extend_from_slice(&[20, 20, 20, 255]);
                    white.extend_from_slice(&[20, 20, 20, 255]);
                } else {
                    // Fully transparent vs explicitly white.
                    clear.extend_from_slice(&[0, 0, 0, 0]);
                    white.extend_from_slice(&[255, 255, 255, 255]);
                }
                let _ = y;
            }
        }
        let a = screenshot_hash(&png_rgba(w, w, &clear)).unwrap();
        let b = screenshot_hash(&png_rgba(w, w, &white)).unwrap();
        assert_eq!(a, b, "transparent must composite to white, not black");
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(screenshot_hash(&[]).is_err());
        assert!(screenshot_hash(b"not a png at all").is_err());
        // A PNG header followed by garbage.
        let mut truncated = png_rgba(8, 8, &[255u8; 8 * 8 * 4]);
        truncated.truncate(40);
        assert!(screenshot_hash(&truncated).is_err());
    }

    #[test]
    fn grouping_collects_templates_largest_first() {
        let login_a = screenshot_hash(&textured(320, 240, 0)).unwrap();
        let login_b = screenshot_hash(&textured(160, 120, 0)).unwrap();
        let login_c = screenshot_hash(&page(320, 240, 0, 0)).unwrap();
        let other = screenshot_hash(&textured(320, 240, 90)).unwrap();

        let groups = group(&[
            ("host-a", login_a),
            ("host-b", login_b),
            ("host-c", login_c),
            ("host-d", other),
        ]);
        assert_eq!(groups.len(), 2, "{groups:?}");
        assert_eq!(groups[0], vec!["host-a", "host-b", "host-c"]);
        assert_eq!(groups[1], vec!["host-d"]);
        // Deterministic.
        assert_eq!(
            groups,
            group(&[
                ("host-d", other),
                ("host-c", login_c),
                ("host-a", login_a),
                ("host-b", login_b),
            ])
        );
        assert!(group::<&str>(&[]).is_empty());
    }

    #[test]
    fn distance_is_symmetric_and_bounded() {
        assert_eq!(distance(0, 0), 0);
        assert_eq!(distance(0, u64::MAX), 64);
        assert_eq!(distance(0b1010, 0b0001), 3);
        assert_eq!(distance(7, 9), distance(9, 7));
    }
}
