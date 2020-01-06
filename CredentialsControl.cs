using System.Linq;
using System.IO;
using System.Threading.Tasks;
using Data.Helpers;
using Data.Models;
using Newtonsoft.Json;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.UserPass;

namespace Data.Security
{
    public class CredentialsControl
    {

        private static UserPassModel ServerCredentials()
        {
            using (StreamReader r = new StreamReader("sec.json"))
            {
                var str = r.ReadToEnd();
                return JsonConvert.DeserializeObject<UserPassModel>(str.ToString());
            }
        }

        public static UserPassModel GetUserPass(string path, string mount)
        {
            IAuthMethodInfo authMethod = new UserPassAuthMethodInfo(ServerCredentials().Username, ServerCredentials().Password);
            var vaultClientSettings = new VaultClientSettings($"http://{Tools.GetEnvString("VAULT_HOST")}:{Tools.GetEnvString("VAULT_PORT")}", authMethod);
            IVaultClient vaultClient = new VaultClient(vaultClientSettings);
            var cred = vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(mount, null, path);
            return new UserPassModel
            {
                Username = cred.Result.Data.Data.FirstOrDefault(x => x.Key.ToLower().Contains("username")).Key != null ? cred.Result.Data.Data.FirstOrDefault(x => x.Key.ToLower().Contains("username")).Value.ToString() : null,
                Password = cred.Result.Data.Data.FirstOrDefault(x => x.Key.ToLower().Contains("password")).Value.ToString() ?? null
            };
        }

        public static ApiAccessModel GetApiAccess(string path, string mount)
        {
            IAuthMethodInfo authMethod = new UserPassAuthMethodInfo(ServerCredentials().Username, ServerCredentials().Password);
            var vaultClientSettings = new VaultClientSettings($"http://{Tools.GetEnvString("VAULT_HOST")}:{Tools.GetEnvString("VAULT_PORT")}", authMethod);
            IVaultClient vaultClient = new VaultClient(vaultClientSettings);
            var cred = vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(mount, null, path);
            return new ApiAccessModel
            {
                Id = cred.Result.Data.Data.FirstOrDefault(x => x.Key.ToLower().Contains("id")).Key != null ? cred.Result.Data.Data.FirstOrDefault(x => x.Key.ToLower().Contains("id")).Value.ToString() : null,
                Secret = cred.Result.Data.Data.FirstOrDefault(x => x.Key.ToLower().Contains("secret")).Value.ToString() ?? null
            };
        }
    }
}