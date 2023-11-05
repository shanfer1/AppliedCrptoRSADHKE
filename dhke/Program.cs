using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// This class handles the key exchange and encryption/decryption using Diffie-Hellman and AES.
class SecretKeyExchange
{
    // Computes the shared secret key using the Diffie-Hellman key exchange algorithm.
    public BigInteger ComputeKey(BigInteger baseExp, BigInteger baseSub, BigInteger modExp, BigInteger modSub, BigInteger privNum, BigInteger pubNumMod)
    {
        // Calculate the base (g) and modulus (N) for Diffie-Hellman from given exponents and subtrahends.
        BigInteger baseValue = BigInteger.Pow(2, (int)baseExp) - baseSub;
        BigInteger modulus = BigInteger.Pow(2, (int)modExp) - modSub;
        
        // Calculate the shared key using the private number and the received public number modulo N.
        BigInteger computedKey = BigInteger.ModPow(pubNumMod, privNum, modulus);
        return computedKey;
    }

    // Encrypts plaintext using AES encryption with the given secret key and initialization vector (IV).
    public byte[] SecureEncrypt(string data, BigInteger secret, byte[] initVector)
    {
        // Initialize the AES encryption algorithm.
        using (Aes encryptionAlgorithm = Aes.Create())
        {
            // Convert the BigInteger key to a byte array and set it as the AES key.
            encryptionAlgorithm.Key = secret.ToByteArray(isUnsigned: true, isBigEndian: false);
            encryptionAlgorithm.IV = initVector;
            encryptionAlgorithm.Mode = CipherMode.CBC; // Set cipher mode to CBC.
            encryptionAlgorithm.Padding = PaddingMode.PKCS7; // Use PKCS7 padding.

            // Create an encryptor object from the AES algorithm with the key and IV.
            ICryptoTransform dataEncryptor = encryptionAlgorithm.CreateEncryptor(encryptionAlgorithm.Key, encryptionAlgorithm.IV);
            
            byte[] result;
            // Create a memory stream to hold the encrypted data.
            using (var memoryStream = new System.IO.MemoryStream())
            {
                // Create a crypto stream that writes the encrypted data to the memory stream.
                using (var cryptoStream = new CryptoStream(memoryStream, dataEncryptor, CryptoStreamMode.Write))
                {
                    // Write the plaintext to the crypto stream, automatically encrypting it in the process.
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(data);
                    }
                    // Convert the written data to a byte array.
                    result = memoryStream.ToArray();
                }
            }

            return result;
        }
    }

    // Decrypts ciphertext using AES decryption with the given secret key and initialization vector (IV).
    public string SecureDecrypt(byte[] encryptedData, BigInteger secret, byte[] initVector)
    {
        // Initialize the AES decryption algorithm.
        using (Aes encryptionAlgorithm = Aes.Create())
        {
            // Convert the BigInteger key to a byte array and set it as the AES key.
            encryptionAlgorithm.Key = secret.ToByteArray(isUnsigned: true, isBigEndian: false);
            encryptionAlgorithm.IV = initVector;
            encryptionAlgorithm.Mode = CipherMode.CBC; // Set cipher mode to CBC.
            encryptionAlgorithm.Padding = PaddingMode.PKCS7; // Use PKCS7 padding.

            // Create a decryptor object from the AES algorithm with the key and IV.
            ICryptoTransform dataDecryptor = encryptionAlgorithm.CreateDecryptor(encryptionAlgorithm.Key, encryptionAlgorithm.IV);
            
            string data = null;
            // Create a memory stream to read the encrypted data.
            using (var memoryStream = new System.IO.MemoryStream(encryptedData))
            {
                // Create a crypto stream that reads and decrypts the data from the memory stream.
                using (var cryptoStream = new CryptoStream(memoryStream, dataDecryptor, CryptoStreamMode.Read))
                {
                    // Read the decrypted plaintext from the crypto stream.
                    using (var streamReader = new StreamReader(cryptoStream))
                    {
                        data = streamReader.ReadToEnd();
                    }
                }
            }

            return data;
        }
    }
}
// The EntryPoint class contains the Main method, which is the entry point of the program.
class EntryPoint
{
    static void Main(string[] parameters)
    {
        // Convert the hex string parameter for the initialization vector to a byte array.
        byte[] vector = ConvertFromHex(parameters[0]);

        // Parse the BigIntegers from the parameters for the Diffie-Hellman key computation.
        BigInteger expBase = BigInteger.Parse(parameters[1]);
        BigInteger subBase = BigInteger.Parse(parameters[2]);
        BigInteger expModulus = BigInteger.Parse(parameters[3]);
        BigInteger subModulus = BigInteger.Parse(parameters[4]);
        BigInteger privateVal = BigInteger.Parse(parameters[5]);
        BigInteger publicValMod = BigInteger.Parse(parameters[6]);

        // Convert the hex string parameter for the encrypted data to a byte array.
        byte[] cipherData = ConvertFromHex(parameters[7]);

        // The eighth parameter is assumed to be plaintext data for encryption.
        string clearData = parameters[8];
        
        // Instantiate the SecretKeyExchange class to access its methods.
        SecretKeyExchange keyExchangeProcess = new SecretKeyExchange();

        // Compute the mutual key using the provided parameters.
        BigInteger mutualKey = keyExchangeProcess.ComputeKey(expBase, subBase, expModulus, subModulus, privateVal, publicValMod);

        // Decrypt the provided cipher data using the mutual key and initialization vector.
        string decryptedData = keyExchangeProcess.SecureDecrypt(cipherData, mutualKey, vector);

        // Encrypt the provided clear data using the mutual key and initialization vector.
        byte[] encryptedData = keyExchangeProcess.SecureEncrypt(clearData, mutualKey, vector);

        // Output the decrypted and encrypted data in a formatted string.
        Console.WriteLine($"{decryptedData}, {BitConverter.ToString(encryptedData).Replace("-", " ")}");
    }

    // Converts a hexadecimal string to a byte array.
    static byte[] ConvertFromHex(string hexString)
    {
        // Remove any spaces from the hex string.
        hexString = hexString.Replace(" ", "");

        // Initialize a byte array to hold the converted hex string.
        byte[] bytesArray = new byte[hexString.Length / 2];

        // Process each hex digit pair.
        for (int index = 0; index < hexString.Length; index += 2)
        {
            // Convert each hex pair (e.g., "1A") to its byte representation and store it in the array.
            bytesArray[index / 2] = Convert.ToByte(hexString.Substring(index, 2), 16);
        }
        
        // Return the byte array representation of the hex string.
        return bytesArray;
    }
}
