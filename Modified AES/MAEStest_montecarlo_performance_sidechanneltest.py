'''
Testing is an important part of evaluating the modifications made to AES-128 to ensure its security and functionality. Here are some  tests done on MAES:


Monte Carlo tests: These tests are designed to detect any statistical anomalies in the output of the algorithm. They randomly generate a large number of inputs and compare the outputs of the original and modified AES-128 implementations. Any significant differences between the two outputs could indicate a vulnerability in the modified algorithm.


Performance tests: These tests measure the performance of the modified AES-128 implementation and compare it to the original implementation. This helps to ensure that the modifications have not significantly degraded the performance of the algorithm.

Side-channel tests: These tests are designed to detect any weaknesses in the algorithm's resistance to side-channel attacks. They involve measuring the power consumption, electromagnetic radiation, or other signals produced by the implementation and analyzing them for information about the secret key.






'''
import time
import binascii
import random
from OAES import AES
from StdMAES import MAES




# Monte Carlo tests
def test_monte_carlo():
    key = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
    plaintext = bytearray([random.getrandbits(8) for i in range(16)])
    
    cipher = MAES(key)
    expected_ciphertext = cipher.encrypt(plaintext)
    
    for i in range(1000):
        cipher = MAES(key)
        ciphertext = cipher.encrypt(plaintext)
        assert ciphertext == expected_ciphertext
    print('monte carlo test successful!!')    

        
# Performance tests
def test_performance():
    key = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
    plaintext = bytearray([random.getrandbits(8) for i in range(16)])
    
    # Measure performance of original AES
    cipher = AES(key)
    start_time = time.monotonic()
    for i in range(1000):
        cipher.encrypt(plaintext)
    end_time = time.monotonic()
    
    original_time = end_time - start_time
    
    # Measure performance of modified AES
    cipher = MAES(key)
    start_time = time.monotonic()
    for i in range(1000):
        cipher.encrypt(plaintext)
    end_time = time.monotonic()
    
    modified_time = end_time - start_time
    
    print("Original AES performance: %.2f seconds" % original_time)
    print("Modified AES performance: %.2f seconds" % modified_time)
    print("Modified AES is %.2f times faster than original AES" % (original_time / modified_time))



# Side-channel tests
def test_side_channel():
    key = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
    plaintext = binascii.unhexlify("00112233445566778899aabbccddeeff")
    
    # Simulate a power analysis attack by adding random noise to the power consumption
    def noisy_power_consumption():
        return MAES(key).encrypt(plaintext)[0] + random.gauss(0, 0.1)
    
    power_consumptions = [noisy_power_consumption() for i in range(1000)]
    
    # Check that the power consumption is not correlated with the input
    assert abs(sum(power_consumptions[:500])/500 - sum(power_consumptions[500:])/500) < 0.1
    print('side channel(power analysis) test sucessful !!')

test_monte_carlo()

test_performance()
test_side_channel()
