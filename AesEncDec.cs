using System.Text;
using System;
using System.Security.Cryptography;

namespace Data.Security
{
    public class AesEncDec : IEncrypt
    {
        private string _text { get; set; }

        public byte[] _key { get; set; }

        private string _cipherText { get; set; }

        public string EncryptString()
        {
            var toEnc = UTF8Encoding.UTF8.GetBytes(_text);
            using (TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider() { Key = _key, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
            {
                ICryptoTransform transform = tripleDES.CreateEncryptor();
                var result = transform.TransformFinalBlock(toEnc, 0, toEnc.Length);
                return Convert.ToBase64String(result, 0, result.Length);
            }
        }

        public string DecryptString()
        {
            var toDec = Convert.FromBase64String(_cipherText);
            using (TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider() { Key = _key, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
            {
                ICryptoTransform transform = tripleDES.CreateDecryptor();
                var result = transform.TransformFinalBlock(toDec, 0, toDec.Length);
                return UTF8Encoding.UTF8.GetString(result);
            }
        }

        public IEncrypt setText(string Text)
        {
            _text = Text;
            return this;
        }

        public IEncrypt setKey(string key)
        {
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                _key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
            }
            return this;
        }

        public IEncrypt setCipherText(string Text)
        {
            _cipherText = Text;
            return this;
        }
    }
}