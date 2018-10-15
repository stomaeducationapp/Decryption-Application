using Microsoft.Win32;
using System.Windows;
using System.Security.Cryptography;
using System;
using System.IO;

namespace Enc_Dec
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string filename;
        Aes aesObj;

        public MainWindow()
        {
            //insantiate the local AES object
            aesObj = Aes.Create();
            aesObj.Padding = PaddingMode.PKCS7;
            InitializeComponent();
        }

        /**
         * Handles the encryption call to encrypt a file for validation
         * */
        private void encrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileBrowser = new OpenFileDialog();
            string file, contents;
            byte[] encrypted;

            if (fileBrowser.ShowDialog() == true)
            {
                file = fileBrowser.FileName;
                contents = File.ReadAllText(file);

                encrypted = encrypt(contents, aesObj.Key, aesObj.IV);

                try
                {
                    file = file.Substring(0, file.Length - 4);
                    File.WriteAllBytes(file + "Encrypt.txt", encrypted);

                    MessageBox.Show("File successfully encrypted");
                }
                catch (IOException) { MessageBox.Show("Problem saving file"); }
            }
        }

        /**
         * Select the file that we want to decrypt
         * */
        private void selectFileToDec_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileBrowser = new OpenFileDialog();

            if (fileBrowser.ShowDialog() == true)
            {
                filename = fileBrowser.FileName;
                filePath.Content = filename;
            }
        }

        /**
         * This method handles decrypting the relevant file after the decrypt button click
         */
        private void decFile_Click(object sender, RoutedEventArgs e)
        {
            byte[] encrypted;
            string decrypted, file;

            if (filename != null)
            {
                try
                {
                    encrypted = File.ReadAllBytes(filename);
                    decrypted = decryptText(encrypted, aesObj.Key, aesObj.IV);

                    file = filename.Substring(0, filename.Length - 11);
                    File.WriteAllText(file + "Decrypt.txt", decrypted);

                    MessageBox.Show("File Decrypted");
                }
                catch (IOException) { MessageBox.Show("Problem saving file"); }
            }
        }

        /**
         * Method to decrypt a byte array into a string
         * Code referenced from: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=netframework-4.7.2
        */
        private string decryptText(byte[] cipherText, byte[] key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = IV;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception e) { MessageBox.Show("Error " + e.Message); }

            return plaintext;
        }

        /**
         * Method to encrypt a string into a byte array
         * Code referenced from: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=netframework-4.7.2
        */
        private byte[] encrypt(string plainText, byte[] key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted = null;

            // Create an Aes object
            // with the specified key and IV.
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }
            }
            catch (Exception e) { MessageBox.Show("Error " + e.Message); }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        /**
        * This method compares the file before and after the encrypt/decrypt process and shows the user if it was successsful
        */
        private void verifyBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string path = System.Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                string before = File.ReadAllText(path + "\\EncDecTest.txt");
                string after = File.ReadAllText(path + "\\EncDecTestDecrypt.txt");

                if (before.Equals(after))
                {
                    MessageBox.Show("File successfully encrypted and decrypted");
                }
                else
                {
                    MessageBox.Show("File could not be encrypted and decrypted");
                }
            }
            catch (IOException) { MessageBox.Show("Problem opening files"); }
        }
    }
}
