def print_hex(name, value, p):
    """Print a value in both decimal and hex form"""
    hex_value = hex(value % p)
    print(f"{name}:")
    print(f"  dec: {value}")
    print(f"  hex: {hex_value}")

def test_sswu(u_value, p, a, b, z):
    print("=== Python Implementation ===")
    print_hex("Input u", u_value, p)
    
    # Calculate m
    m = (pow(z, 2, p) * pow(u_value, 4, p) + z * pow(u_value, 2, p)) % p
    print_hex("m", m, p)
    
    # Calculate t
    t = pow(m, p - 2, p) if m != 0 else 0
    print_hex("t", t, p)
    
    # Calculate x1
    if m == 0:
        x1 = (b * pow(z * a, p - 2, p)) % p
    else:
        x1 = (-b * (1 + t) * pow(a, p - 2, p)) % p
    print_hex("x1", x1, p)
    
    # Calculate gx1
    gx1 = (pow(x1, 3, p) + a * x1 + b) % p
    print_hex("gx1", gx1, p)
    
    # Calculate x2
    x2 = (z * pow(u_value, 2, p) * x1) % p
    print_hex("x2", x2, p)
    
    # Calculate gx2
    gx2 = (pow(x2, 3, p) + a * x2 + b) % p
    print_hex("gx2", gx2, p)
    
    return m, t, x1, gx1, x2, gx2

# secp256r1 parameters
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
z = -10

# Test vectors
test_values = [
    123456789,
    0xdeadbeef,
    0x1234567890abcdef
]

print("Running test vectors...")
for u in test_values:
    m, t, x1, gx1, x2, gx2 = test_sswu(u, p, a, b, z)
    print("\n---\n")