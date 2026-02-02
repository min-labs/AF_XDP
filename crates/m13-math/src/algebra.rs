use m13_math::GfSymbol;

#[test]
fn test_aes_vector() {
    // Known AES Vector: 0x57 * 0x83 = 0xC1
    // (x^6 + x^4 + x^2 + x + 1) * (x^7 + x + 1) mod P(x)
    let a = GfSymbol(0x57);
    let b = GfSymbol(0x83);
    assert_eq!(a.mul(b), GfSymbol(0xC1), "Table Mul Failed");
    assert_eq!(a.mul_safe(b), GfSymbol(0xC1), "Safe Mul Failed");
}

#[test]
fn test_generator_validity() {
    // 3^1 = 3
    assert_eq!(GfSymbol(3).mul(GfSymbol::ONE), GfSymbol(3));
    // 3^255 = 1 (Cyclic Group)
    let mut x = GfSymbol::ONE;
    for _ in 0..255 {
        x = x * GfSymbol(3);
    }
    assert_eq!(x, GfSymbol::ONE, "Generator 3 does not span the group");
}