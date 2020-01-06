namespace Data.Security
{
    public interface IEncrypt
    {
        string EncryptString();
        string DecryptString();

        IEncrypt setText(string Text);

        IEncrypt setKey(string key);

        IEncrypt setCipherText(string Text);
    }
}