using System;
using System.Numerics;

class Program {
    static void Main(string[] args) {
        // Assuming the command line arguments are provided in the correct order and format.
        
        // Parse the arguments provided to the program to obtain the parameters needed for RSA encryption/decryption.
        BigInteger primeExponentP = BigInteger.Parse(args[0]);
        BigInteger primeConstantP = BigInteger.Parse(args[1]);
        BigInteger primeExponentQ = BigInteger.Parse(args[2]);
        BigInteger primeConstantQ = BigInteger.Parse(args[3]);
        BigInteger exponentE = BigInteger.Parse(args[4]);
        BigInteger constantE = BigInteger.Parse(args[5]);
        string cipherTextHex = args[6];
        string plainTextMessage = args[7];

        // Compute the prime numbers p and q using the provided exponents and constants.
        // This likely represents a scheme to derive the primes based on predefined constants.
        BigInteger primeP = BigInteger.Pow(2, (int)primeExponentP) - primeConstantP;
        BigInteger primeQ = BigInteger.Pow(2, (int)primeExponentQ) - primeConstantQ;
        BigInteger exponentiationE = BigInteger.Pow(2, (int)exponentE) - constantE;

        // Calculate the modulus N, which is the product of the two primes p and q.
        // This modulus is used in the RSA encryption and decryption algorithms.
        BigInteger modulusN = primeP * primeQ;

        // Generate the private key exponent d using the RSA algorithm,
        // which requires the modular inverse of e with respect to (p-1)*(q-1).
        BigInteger privateKeyD = GeneratePrivateKey(exponentiationE, primeP, primeQ);

        // Decrypt the provided ciphertext using the private key exponent d and modulus N.
        // The decrypted text should be the original plaintext if the ciphertext was encrypted with the corresponding public key.
        string decryptedText = Decrypt(cipherTextHex, privateKeyD, modulusN);

        // Encrypt the provided plaintext message using the public exponent e and modulus N.
        // The resulting ciphertext can only be decrypted with the corresponding private key.
        string encryptedCipher = Encrypt(plainTextMessage, exponentiationE, modulusN);

        // Output the decrypted plaintext and the encrypted cipher as a comma-separated pair.
        Console.WriteLine($"{decryptedText},{encryptedCipher}");
    }

    // Generates the private key for RSA decryption by calculating the modular inverse of e.
    public static BigInteger GeneratePrivateKey(BigInteger publicExponentE, BigInteger primeP, BigInteger primeQ) {
        BigInteger phiN = (primeP - 1) * (primeQ - 1); // Compute Euler's totient function (phi(N))
        BigInteger privateKeyD = ModInverse(publicExponentE, phiN); // Modular inverse of e mod phi(N)
        return privateKeyD;
    }

    // Calculates the modular inverse of a number with respect to a modulus.
    private static BigInteger ModInverse(BigInteger number, BigInteger modulus) {
        BigInteger xOut, yOut;
        BigInteger gcd = ExtendedEuclid(number, modulus, out xOut, out yOut); // Extended Euclidean Algorithm
        if (gcd != 1)
            throw new ArgumentException("No modular inverse exists."); // Modular inverse does not exist if gcd is not 1
        return (xOut % modulus + modulus) % modulus; // Ensure the result is positive
    }

    // Performs the Extended Euclidean Algorithm to find the GCD of two numbers and the coefficients (x and y) for Bézout's identity.
    private static BigInteger ExtendedEuclid(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y) {
        if (a == 0) {
            x = 0;
            y = 1; // Base case for recursion
            return b;
        }
        BigInteger xTemp, yTemp;
        BigInteger gcd = ExtendedEuclid(b % a, a, out xTemp, out yTemp); // Recursive call

        // Update x and y using the results of recursion
        x = yTemp - (b / a) * xTemp;
        y = xTemp;
        return gcd;
    }

    // Decrypts ciphertext using RSA decryption algorithm with private key (d, N).
    public static string Decrypt(string cipherTextHex, BigInteger decryptionKeyD, BigInteger modulusN) {
        BigInteger cipherInt = BigInteger.Parse(cipherTextHex); // Convert hex string to BigInteger
        BigInteger plainInt = BigInteger.ModPow(cipherInt, decryptionKeyD, modulusN); // RSA decryption
        return plainInt.ToString(); // Convert decrypted BigInteger back to string
    }

    public static string Encrypt(string plainTextMessage, BigInteger encryptionKeyE, BigInteger modulusN) {
        BigInteger plainInt = BigInteger.Parse(plainTextMessage);
        BigInteger cipherInt = BigInteger.ModPow(plainInt, encryptionKeyE, modulusN);
        return cipherInt.ToString();
    }
}
