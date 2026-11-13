// Launcher do DiskTool: extrai o DiskTool.ps1 embutido e o executa com o PowerShell do Windows, sem console.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("DiskTool")]
[assembly: AssemblyDescription("Saúde e formatação de discos (NVMe / SSD / HDD)")]
[assembly: AssemblyProduct("DiskTool")]
[assembly: AssemblyVersion("2.8.0.0")]
[assembly: AssemblyFileVersion("2.8.0.0")]

static class Program
{
    // Repassa só as opções conhecidas (ex.: -Monitor, usado pela tarefa agendada).
    static string ExtraArgs(string[] args)
    {
        foreach (string a in args)
            if (string.Equals(a, "-Monitor", StringComparison.OrdinalIgnoreCase)) return " -Monitor";
        return "";
    }

    [STAThread]
    static int Main(string[] args)
    {
        string exe = Assembly.GetExecutingAssembly().Location;
        string dir = Path.GetDirectoryName(exe).TrimEnd('\\');
        string tmpDir = Path.Combine(Path.GetTempPath(), "DiskTool_" + Guid.NewGuid().ToString("N"));
        string ps1 = Path.Combine(tmpDir, "DiskTool.ps1");
        StringBuilder stderr = new StringBuilder();

        try
        {
            Directory.CreateDirectory(tmpDir);
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("DiskTool.ps1"))
            using (FileStream f = File.Create(ps1))
                s.CopyTo(f);

            ProcessStartInfo psi = new ProcessStartInfo(
                Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File \"" + ps1 +
                "\" -AppDir \"" + dir + "\" -AppExe \"" + exe + "\"" + ExtraArgs(args));
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardError = true;

            using (Process p = new Process())
            {
                p.StartInfo = psi;
                p.ErrorDataReceived += (o, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };
                p.Start();
                p.BeginErrorReadLine();
                p.WaitForExit();
                if (p.ExitCode != 0 && stderr.Length > 0)
                    MessageBox.Show(stderr.ToString(), "DiskTool - erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return p.ExitCode;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "DiskTool - erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        finally
        {
            try { Directory.Delete(tmpDir, true); } catch { }
        }
    }
}
