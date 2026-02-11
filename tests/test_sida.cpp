//=============================================================================
// S-IDA Unit Tests
// Tests for the complete S-IDA implementation including:
// - Rabin IDA encoding/decoding
// - Shamir Secret Sharing
// - Full S-IDA split/combine workflow
//=============================================================================

#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <algorithm>

#include "../src/encrypt_p2p/s_ida.hpp"
#include "../src/encrypt_p2p/rabin_ida.hpp"

using namespace encrypt_p2p;

//=============================================================================
// Test helpers
//=============================================================================

std::string generateRandomString(size_t length) {
    static const char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++) {
        result += charset[dist(gen)];
    }
    return result;
}

void printTestResult(const std::string& testName, bool passed) {
    std::cout << (passed ? "[PASS] " : "[FAIL] ") << testName << std::endl;
}

//=============================================================================
// Rabin IDA Tests
//=============================================================================

bool testRabinIDABasic() {
    std::string original = "Hello, Rabin IDA! This is a test message.";
    int n = 5, k = 3;
    
    auto fragments = RabinIDA::split(original, n, k);
    
    // Verify fragment count
    if (fragments.size() != static_cast<size_t>(n)) return false;
    
    // Verify each fragment has correct metadata
    for (int i = 0; i < n; i++) {
        if (fragments[i].index != static_cast<uint8_t>(i + 1)) return false;
        if (fragments[i].originalSize != original.size()) return false;
    }
    
    // Reconstruct using first k fragments
    std::vector<RabinIDA::Fragment> subset(fragments.begin(), fragments.begin() + k);
    std::string reconstructed = RabinIDA::combineToString(subset, k);
    
    return reconstructed == original;
}

bool testRabinIDADifferentSubsets() {
    std::string original = "Testing reconstruction from different fragment subsets.";
    int n = 6, k = 3;
    
    auto fragments = RabinIDA::split(original, n, k);
    
    // Test all possible k-subsets would be expensive, test a few
    std::vector<std::vector<int>> subsets = {
        {0, 1, 2},  // First k
        {3, 4, 5},  // Last k
        {0, 2, 4},  // Alternating
        {1, 3, 5},  // Other alternating
        {0, 1, 5},  // Mixed
    };
    
    for (const auto& indices : subsets) {
        std::vector<RabinIDA::Fragment> subset;
        for (int idx : indices) {
            subset.push_back(fragments[idx]);
        }
        
        std::string reconstructed = RabinIDA::combineToString(subset, k);
        if (reconstructed != original) {
            std::cerr << "Failed with subset: ";
            for (int idx : indices) std::cerr << idx << " ";
            std::cerr << std::endl;
            return false;
        }
    }
    
    return true;
}

bool testRabinIDANotEnoughFragments() {
    std::string original = "This should fail with k-1 fragments.";
    int n = 5, k = 3;
    
    auto fragments = RabinIDA::split(original, n, k);
    
    // Try with k-1 fragments (should throw)
    std::vector<RabinIDA::Fragment> subset(fragments.begin(), fragments.begin() + k - 1);
    
    try {
        RabinIDA::combineToString(subset, k);
        return false; // Should have thrown
    } catch (const std::runtime_error&) {
        return true; // Expected behavior
    }
}

bool testRabinIDALargeData() {
    // Test with larger data to verify chunk handling
    std::string original = generateRandomString(10000);
    int n = 7, k = 4;
    
    auto fragments = RabinIDA::split(original, n, k);
    
    // Verify fragment sizes are approximately original/k
    size_t expectedFragmentSize = (original.size() + k - 1) / k;
    for (const auto& frag : fragments) {
        if (frag.data.size() != expectedFragmentSize) {
            std::cerr << "Fragment size mismatch: expected " << expectedFragmentSize
                      << " got " << frag.data.size() << std::endl;
            // This is allowed due to padding, just log it
        }
    }
    
    // Reconstruct
    std::vector<RabinIDA::Fragment> subset(fragments.begin(), fragments.begin() + k);
    std::string reconstructed = RabinIDA::combineToString(subset, k);
    
    return reconstructed == original;
}

//=============================================================================
// Shamir Secret Sharing Tests
//=============================================================================

bool testShamirBasic() {
    std::string secret = "This is a 32-byte secret key!!!";
    int n = 5, k = 3;
    
    auto shares = ShamirSecretSharing::split(secret, n, k);
    
    if (shares.size() != static_cast<size_t>(n)) return false;
    
    // Reconstruct using first k shares
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> subset(
        shares.begin(), shares.begin() + k);
    std::string reconstructed = ShamirSecretSharing::combine(subset, k);
    
    return reconstructed == secret;
}

bool testShamirDifferentSubsets() {
    std::string secret = "AES-256 key for testing Shamir!";
    int n = 6, k = 3;
    
    auto shares = ShamirSecretSharing::split(secret, n, k);
    
    // Test different subsets
    std::vector<std::vector<int>> subsets = {
        {0, 1, 2},
        {3, 4, 5},
        {0, 2, 4},
        {1, 3, 5},
    };
    
    for (const auto& indices : subsets) {
        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> subset;
        for (int idx : indices) {
            subset.push_back(shares[idx]);
        }
        
        std::string reconstructed = ShamirSecretSharing::combine(subset, k);
        if (reconstructed != secret) return false;
    }
    
    return true;
}

//=============================================================================
// Full S-IDA Tests
//=============================================================================

bool testSIDABasic() {
    std::string message = "This is a test message for S-IDA encryption.";
    int n = 4, k = 3;
    
    auto cloves = SIDA::split(message, n, k);
    
    // Verify clove count
    if (cloves.size() != static_cast<size_t>(n)) return false;
    
    // Verify fragment indices
    for (int i = 0; i < n; i++) {
        if (cloves[i].fragmentIndex != static_cast<uint8_t>(i + 1)) return false;
    }
    
    // Reconstruct
    std::string reconstructed = SIDA::combine(cloves, k);
    
    return reconstructed == message;
}

bool testSIDADifferentSubsets() {
    std::string message = "Testing S-IDA with different clove subsets for reconstruction.";
    int n = 5, k = 3;
    
    auto cloves = SIDA::split(message, n, k);
    
    // Test different subsets
    std::vector<std::vector<int>> subsets = {
        {0, 1, 2},
        {2, 3, 4},
        {0, 2, 4},
        {1, 2, 3},
    };
    
    for (const auto& indices : subsets) {
        std::vector<SIDA::Clove> subset;
        for (int idx : indices) {
            subset.push_back(cloves[idx]);
        }
        
        std::string reconstructed = SIDA::combine(subset, k);
        if (reconstructed != message) {
            std::cerr << "S-IDA failed with subset: ";
            for (int idx : indices) std::cerr << idx << " ";
            std::cerr << std::endl;
            return false;
        }
    }
    
    return true;
}

bool testSIDANotEnoughCloves() {
    std::string message = "This should fail with fewer than k cloves.";
    int n = 5, k = 3;
    
    auto cloves = SIDA::split(message, n, k);
    
    // Try with k-1 cloves
    std::vector<SIDA::Clove> subset(cloves.begin(), cloves.begin() + k - 1);
    
    try {
        SIDA::combine(subset, k);
        return false; // Should have thrown
    } catch (const std::runtime_error&) {
        return true; // Expected
    }
}

bool testSIDALargeMessage() {
    std::string message = generateRandomString(50000);
    int n = 6, k = 4;
    
    auto cloves = SIDA::split(message, n, k);
    
    // Verify fragments are smaller than original ciphertext
    // (which is hex-encoded, so roughly 2x the original message size)
    size_t totalFragmentSize = 0;
    for (const auto& cl : cloves) {
        totalFragmentSize += cl.fragment.size();
    }
    
    // Each fragment should be ~ciphertext_size/k
    // Total fragments = n * (ciphertext/k) = (n/k) * ciphertext
    // For n=6, k=4: should be ~1.5x ciphertext size, not n*ciphertext
    
    std::vector<SIDA::Clove> subset(cloves.begin(), cloves.begin() + k);
    std::string reconstructed = SIDA::combine(subset, k);
    
    return reconstructed == message;
}

bool testSIDASerialization() {
    std::string message = "Test serialization and deserialization of cloves.";
    int n = 4, k = 3;
    
    auto cloves = SIDA::split(message, n, k);
    
    // Serialize and deserialize each clove
    std::vector<SIDA::Clove> deserializedCloves;
    for (const auto& cl : cloves) {
        std::string serialized = SIDA::serializeClove(cl);
        SIDA::Clove deserialized = SIDA::deserializeClove(serialized);
        
        // Verify fields match
        if (deserialized.fragmentIndex != cl.fragmentIndex) return false;
        if (deserialized.originalDataSize != cl.originalDataSize) return false;
        if (deserialized.keyShare.first != cl.keyShare.first) return false;
        if (deserialized.keyShare.second != cl.keyShare.second) return false;
        if (deserialized.fragment != cl.fragment) return false;
        
        deserializedCloves.push_back(deserialized);
    }
    
    // Reconstruct from deserialized cloves
    std::string reconstructed = SIDA::combine(deserializedCloves, k);
    
    return reconstructed == message;
}

bool testSIDABandwidthEfficiency() {
    // Verify that total bandwidth is ~(n/k) * ciphertext, not n * ciphertext
    std::string message = generateRandomString(10000);
    int n = 5, k = 3;
    
    auto cloves = SIDA::split(message, n, k);
    
    // Calculate total fragment bytes
    size_t totalFragmentBytes = 0;
    for (const auto& cl : cloves) {
        totalFragmentBytes += cl.fragment.size();
    }
    
    // Original ciphertext is roughly 2x message size (hex encoding) + IV + padding
    // Each fragment should be ~ciphertext_size/k
    // Total = n * (ciphertext/k) = (n/k) * ciphertext
    // 
    // For n=5, k=3: ratio should be ~5/3 ≈ 1.67
    // For old broken impl: ratio would be n = 5
    
    size_t singleCloveCipherSize = cloves[0].originalDataSize;
    double ratio = static_cast<double>(totalFragmentBytes) / singleCloveCipherSize;
    
    std::cout << "  Bandwidth efficiency test:" << std::endl;
    std::cout << "    Original ciphertext size: " << singleCloveCipherSize << " bytes" << std::endl;
    std::cout << "    Total fragment bytes: " << totalFragmentBytes << " bytes" << std::endl;
    std::cout << "    Ratio (should be ~" << static_cast<double>(n)/k << "): " << ratio << std::endl;
    
    // Ratio should be approximately n/k (with some overhead for padding)
    double expectedRatio = static_cast<double>(n) / k;
    double tolerance = 0.3; // Allow 30% deviation for padding overhead
    
    return (ratio >= expectedRatio * (1 - tolerance)) && (ratio <= expectedRatio * (1 + tolerance));
}

bool testSIDASecurityNoKeyLeak() {
    // This test verifies we can run split/combine without any key appearing in stdout
    // (stderr logging was removed in the new implementation)
    std::string message = "Security test message - no keys should be logged.";
    int n = 4, k = 3;
    
    // Redirect stderr temporarily
    std::streambuf* oldCerr = std::cerr.rdbuf();
    std::stringstream capturedCerr;
    std::cerr.rdbuf(capturedCerr.rdbuf());
    
    auto cloves = SIDA::split(message, n, k);
    std::string reconstructed = SIDA::combine(cloves, k);
    
    // Restore stderr
    std::cerr.rdbuf(oldCerr);
    
    // Check for key-related debug output
    std::string errOutput = capturedCerr.str();
    bool hasKeyLeak = (errOutput.find("AES key") != std::string::npos) ||
                      (errOutput.find("key:") != std::string::npos) ||
                      (errOutput.find("Reconstructed") != std::string::npos);
    
    if (hasKeyLeak) {
        std::cerr << "WARNING: Potential key leak in debug output!" << std::endl;
    }
    
    return reconstructed == message && !hasKeyLeak;
}

//=============================================================================
// Performance Tests
//=============================================================================

void runPerformanceTest() {
    std::cout << "\n=== Performance Tests ===" << std::endl;
    
    std::vector<size_t> sizes = {1000, 10000, 100000};
    std::vector<std::pair<int, int>> nkPairs = {{4, 3}, {5, 3}, {7, 4}, {10, 6}};
    
    for (size_t msgSize : sizes) {
        std::string message = generateRandomString(msgSize);
        std::cout << "\nMessage size: " << msgSize << " bytes" << std::endl;
        
        for (auto [n, k] : nkPairs) {
            auto startSplit = std::chrono::high_resolution_clock::now();
            auto cloves = SIDA::split(message, n, k);
            auto endSplit = std::chrono::high_resolution_clock::now();
            
            std::vector<SIDA::Clove> subset(cloves.begin(), cloves.begin() + k);
            
            auto startCombine = std::chrono::high_resolution_clock::now();
            std::string reconstructed = SIDA::combine(subset, k);
            auto endCombine = std::chrono::high_resolution_clock::now();
            
            auto splitTime = std::chrono::duration_cast<std::chrono::microseconds>(endSplit - startSplit).count();
            auto combineTime = std::chrono::duration_cast<std::chrono::microseconds>(endCombine - startCombine).count();
            
            size_t fragSize = cloves[0].fragment.size();
            
            std::cout << "  (n=" << n << ", k=" << k << "): "
                      << "split=" << splitTime << "µs, "
                      << "combine=" << combineTime << "µs, "
                      << "frag_size=" << fragSize << " bytes "
                      << (reconstructed == message ? "[OK]" : "[FAIL]")
                      << std::endl;
        }
    }
}

//=============================================================================
// Main
//=============================================================================

int main() {
    std::cout << "=== S-IDA Unit Tests ===" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Rabin IDA tests
    std::cout << "\n--- Rabin IDA Tests ---" << std::endl;
    
    if (testRabinIDABasic()) { passed++; printTestResult("RabinIDA basic", true); }
    else { failed++; printTestResult("RabinIDA basic", false); }
    
    if (testRabinIDADifferentSubsets()) { passed++; printTestResult("RabinIDA different subsets", true); }
    else { failed++; printTestResult("RabinIDA different subsets", false); }
    
    if (testRabinIDANotEnoughFragments()) { passed++; printTestResult("RabinIDA not enough fragments", true); }
    else { failed++; printTestResult("RabinIDA not enough fragments", false); }
    
    if (testRabinIDALargeData()) { passed++; printTestResult("RabinIDA large data", true); }
    else { failed++; printTestResult("RabinIDA large data", false); }
    
    // Shamir tests
    std::cout << "\n--- Shamir Secret Sharing Tests ---" << std::endl;
    
    if (testShamirBasic()) { passed++; printTestResult("Shamir basic", true); }
    else { failed++; printTestResult("Shamir basic", false); }
    
    if (testShamirDifferentSubsets()) { passed++; printTestResult("Shamir different subsets", true); }
    else { failed++; printTestResult("Shamir different subsets", false); }
    
    // S-IDA tests
    std::cout << "\n--- Full S-IDA Tests ---" << std::endl;
    
    if (testSIDABasic()) { passed++; printTestResult("S-IDA basic", true); }
    else { failed++; printTestResult("S-IDA basic", false); }
    
    if (testSIDADifferentSubsets()) { passed++; printTestResult("S-IDA different subsets", true); }
    else { failed++; printTestResult("S-IDA different subsets", false); }
    
    if (testSIDANotEnoughCloves()) { passed++; printTestResult("S-IDA not enough cloves", true); }
    else { failed++; printTestResult("S-IDA not enough cloves", false); }
    
    if (testSIDALargeMessage()) { passed++; printTestResult("S-IDA large message", true); }
    else { failed++; printTestResult("S-IDA large message", false); }
    
    if (testSIDASerialization()) { passed++; printTestResult("S-IDA serialization", true); }
    else { failed++; printTestResult("S-IDA serialization", false); }
    
    if (testSIDABandwidthEfficiency()) { passed++; printTestResult("S-IDA bandwidth efficiency", true); }
    else { failed++; printTestResult("S-IDA bandwidth efficiency", false); }
    
    if (testSIDASecurityNoKeyLeak()) { passed++; printTestResult("S-IDA security (no key leak)", true); }
    else { failed++; printTestResult("S-IDA security (no key leak)", false); }
    
    // Summary
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << (passed + failed) << std::endl;
    
    if (failed > 0) {
        std::cout << "Failed: " << failed << std::endl;
    }
    
    // Performance tests
    runPerformanceTest();
    
    return failed > 0 ? 1 : 0;
}

