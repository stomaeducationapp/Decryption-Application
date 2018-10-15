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
    }
}
